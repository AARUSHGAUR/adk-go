// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzTruncateForError: the cap must hold, the result must stay a prefix of the
// input, and valid UTF-8 must not be sliced into a mangled rune.
func FuzzTruncateForError(f *testing.F) {
	f.Add("")
	f.Add("nope")
	f.Add(strings.Repeat("a", 2000))
	f.Add(strings.Repeat("\x80", 2000))
	f.Add(strings.Repeat("é", 2000))
	f.Add(strings.Repeat("𝔘", 2000)) // 4-byte runes
	f.Add(strings.Repeat("a", maxErrorBytes-1) + "€")
	f.Add(strings.Repeat("a", maxErrorBytes-3) + "𝔘xyz")
	f.Fuzz(func(t *testing.T, s string) {
		got := truncateForError(s)
		if len(got) > maxErrorBytes+3 {
			t.Fatalf("truncateForError(%d bytes) = %d bytes, want at most %d", len(s), len(got), maxErrorBytes+3)
		}
		body := strings.TrimSuffix(got, "...")
		if !strings.HasPrefix(s, body) {
			t.Fatalf("result %q is not a prefix of the input", body)
		}
		if utf8.ValidString(s) && !utf8.ValidString(body) {
			t.Fatalf("valid UTF-8 input was truncated into invalid UTF-8 (input %d bytes, cut at %d)", len(s), len(body))
		}
	})
}

// FuzzResourceNameURL is the security-critical one: any resource
// RetrieveCredential accepts must not be able to move the request off the
// configured host, add a query or fragment, escape the version prefix, or change
// the method suffix.
func FuzzResourceNameURL(f *testing.F) {
	f.Add(authProviderResource)
	f.Add(connectorResource)
	f.Add("//evil.example.com/x")
	f.Add("a/./b")
	f.Add("...")
	f.Add("/")
	f.Add("projects/p/locations/l/authProviders/a?x=1")
	f.Add("projects/p/locations/l/authProviders/a#f")
	f.Add("projects/p/locations/l/connectors/co/")

	type seen struct{ host, path, rawQuery, fragment string }
	var got seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = seen{r.Host, r.URL.Path, r.URL.RawQuery, r.URL.Fragment}
		_, _ = w.Write([]byte(`{"success":{"token":"t","header":"Authorization: Bearer"}}`))
	}))
	defer srv.Close()
	base, err := url.Parse(srv.URL)
	if err != nil {
		f.Fatal(err)
	}
	c, err := NewClient(f.Context(), &Config{
		HTTPClient:            &http.Client{},
		AgentIdentityEndpoint: srv.URL,
		ConnectorEndpoint:     srv.URL,
		PollTimeout:           50 * time.Millisecond,
	})
	if err != nil {
		f.Fatal(err)
	}
	c.initialBackoff = time.Millisecond

	f.Fuzz(func(t *testing.T, resource string) {
		got = seen{}
		if _, err := c.RetrieveCredential(t.Context(), Request{Resource: resource, UserID: "u"}); err != nil {
			return // rejected or failed; only accepted requests carry the invariant
		}
		if got.host != base.Host {
			t.Fatalf("resource %q sent the credential request to host %q, want %q", resource, got.host, base.Host)
		}
		if got.rawQuery != "" || got.fragment != "" {
			t.Fatalf("resource %q injected query=%q fragment=%q", resource, got.rawQuery, got.fragment)
		}
		if !strings.HasPrefix(got.path, "/v1/") && !strings.HasPrefix(got.path, "/v1alpha/") {
			t.Fatalf("resource %q escaped the version prefix: path=%q", resource, got.path)
		}
		if !strings.HasSuffix(got.path, "/credentials:retrieve") {
			t.Fatalf("resource %q changed the method: path=%q", resource, got.path)
		}
	})
}

// FuzzMapCredential: a service-controlled {header, token} pair must either be
// rejected or produce a credential that a real transport accepts.
//
// The oracle is an actual round trip, not http.Request.Write: Write replaces
// CR/LF with spaces, so it can never observe the header break this is guarding
// against.
func FuzzMapCredential(f *testing.F) {
	f.Add("Authorization: Bearer", "tok")
	f.Add("X-Goog-Api-Key", "k")
	f.Add("X-Bad Header", "k")
	f.Add("Authorization:Bearer", "t")
	f.Add("authorization: bearerX", "t")
	f.Add("X\r\nInjected: 1", "t")
	f.Add("X-Api-Key", "tok\r\nX-Evil: 1")

	var seenHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
	}))
	defer srv.Close()

	f.Fuzz(func(t *testing.T, header, token string) {
		cred, err := mapCredential(header, token)
		if err != nil {
			return
		}
		if cred == nil {
			t.Fatal("mapCredential returned a nil credential and a nil error")
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if err := cred.Apply(req.Header); err != nil {
			return
		}
		seenHeaders = nil
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("mapCredential(%q, %q) produced a credential the transport refused: %v", header, token, err)
		}
		_ = resp.Body.Close()
		// A forged header would arrive as an extra key the credential never named.
		for k := range seenHeaders {
			if strings.EqualFold(k, "X-Evil") || strings.EqualFold(k, "Injected") {
				t.Fatalf("mapCredential(%q, %q) smuggled header %q onto the request", header, token, k)
			}
		}
	})
}

// FuzzDecodeResponse: arbitrary service bytes must never panic the decode path,
// and must never yield a credential with no error.
func FuzzDecodeResponse(f *testing.F) {
	f.Add(`{"success":{"token":"t","header":"Authorization: Bearer"}}`)
	f.Add(`{"pending":{}}`)
	f.Add(`{"done":true,"response":{"token":"t","header":"X-K"}}`)
	f.Add(`{"metadata":{"uriConsentRequired":{"authorizationUri":"https://c.example"}}}`)
	f.Add(`{"error":{"code":7,"message":"x"}}`)
	f.Add(`null`)
	f.Add(`[]`)
	f.Add(`{"success":{"token":"t","header":"Authorization: Bearer","expireTime":"nope"}}`)

	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c, err := NewClient(f.Context(), &Config{
		HTTPClient:            &http.Client{},
		AgentIdentityEndpoint: srv.URL,
		ConnectorEndpoint:     srv.URL,
		PollTimeout:           20 * time.Millisecond,
	})
	if err != nil {
		f.Fatal(err)
	}
	c.initialBackoff = time.Millisecond

	f.Fuzz(func(t *testing.T, reply string) {
		body = reply
		for _, res := range []string{authProviderResource, connectorResource} {
			got, err := c.RetrieveCredential(t.Context(), Request{Resource: res, UserID: "u"})
			switch {
			case err == nil && got == nil:
				t.Fatalf("reply %q: nil result with a nil error", reply)
			case err == nil && got.Credential == nil:
				t.Fatalf("reply %q: result with no credential and a nil error", reply)
			case err == nil:
				_ = got.Credential.Apply(http.Header{})
			}
		}
	})
}
