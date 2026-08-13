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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"google.golang.org/adk/v2/auth"
)

const (
	authProviderResource = "projects/p/locations/l/authProviders/ap"
	connectorResource    = "projects/p/locations/l/connectors/co"
)

// fakeService is a credential service that replays bodies in order and records
// what it was asked. Unlike a server that repeats its last reply forever, it
// fails the test on an unexpected extra call, so a change in the number of round
// trips cannot pass unnoticed.
type fakeService struct {
	*httptest.Server
	mu       sync.Mutex
	bodies   []string
	calls    int
	requests []recordedRequest
}

type recordedRequest struct {
	host, path, method, contentType, accept string
	body                                    retrieveRequest
	at                                      time.Time
}

func newFakeService(t *testing.T, bodies ...string) *fakeService {
	t.Helper()
	f := &fakeService{bodies: bodies}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		rec := recordedRequest{
			host: r.Host, path: r.URL.Path, method: r.Method,
			contentType: r.Header.Get("Content-Type"), accept: r.Header.Get("Accept"),
			at: time.Now(),
		}
		_ = json.NewDecoder(r.Body).Decode(&rec.body)
		f.requests = append(f.requests, rec)
		i := f.calls
		f.calls++
		if i >= len(f.bodies) {
			// t.Errorf, not Fatal: this runs on the server's goroutine.
			t.Errorf("credential service called %d time(s), but only %d reply body(ies) were staged", f.calls, len(f.bodies))
			w.WriteHeader(http.StatusTeapot)
			return
		}
		_, _ = io.WriteString(w, f.bodies[i])
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeService) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeService) recorded() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// newTestClient points both endpoints at the same fake and uses a tiny backoff.
func newTestClient(t *testing.T, f *fakeService) *Client {
	t.Helper()
	return newTestClientFor(t, f.URL, f.URL)
}

func newTestClientFor(t *testing.T, agentIdentityURL, connectorURL string) *Client {
	t.Helper()
	c, err := NewClient(t.Context(), &Config{
		HTTPClient:            &http.Client{},
		AgentIdentityEndpoint: agentIdentityURL,
		ConnectorEndpoint:     connectorURL,
		PollTimeout:           2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c.initialBackoff = time.Millisecond
	return c
}

// TestRetrieveCredential drives RetrieveCredential end to end for both services.
// Every case supplies its own check, so a case cannot silently assert nothing.
func TestRetrieveCredential(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		bodies    []string
		wantCalls int
		check     func(t *testing.T, res *Result, err error)
	}{
		// Agent Identity: synchronous "result" oneof.
		{
			name:      "agent identity bearer",
			resource:  authProviderResource,
			bodies:    []string{`{"success":{"token":"tok","header":"Authorization: Bearer"}}`},
			wantCalls: 1,
			check: func(t *testing.T, res *Result, err error) {
				mustSucceed(t, res, err)
				wantBearer(t, res.Credential, "tok")
			},
		},
		{
			name:      "agent identity custom header",
			resource:  authProviderResource,
			bodies:    []string{`{"success":{"token":"KEY","header":"X-Goog-Api-Key"}}`},
			wantCalls: 1,
			check: func(t *testing.T, res *Result, err error) {
				mustSucceed(t, res, err)
				wantAPIKey(t, res.Credential, "X-Goog-Api-Key", "KEY")
			},
		},
		{
			name:      "agent identity carries scopes and expiry",
			resource:  authProviderResource,
			bodies:    []string{`{"success":{"token":"tok","header":"Authorization: Bearer","scopes":["a","b"],"expireTime":"2031-04-05T06:07:08Z"}}`},
			wantCalls: 1,
			check: func(t *testing.T, res *Result, err error) {
				mustSucceed(t, res, err)
				if !slices.Equal(res.Scopes, []string{"a", "b"}) {
					t.Errorf("Scopes = %q, want [a b]", res.Scopes)
				}
				want := time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC)
				if !res.Expiry.Equal(want) {
					t.Errorf("Expiry = %v, want %v", res.Expiry, want)
				}
			},
		},
		{
			// A grant narrower than the request must reach the caller intact: it
			// is the only way to honour the service's instruction to verify scopes.
			name:      "agent identity reports a downgraded scope grant",
			resource:  authProviderResource,
			bodies:    []string{`{"success":{"token":"tok","header":"Authorization: Bearer","scopes":["read"]}}`},
			wantCalls: 1,
			check: func(t *testing.T, res *Result, err error) {
				mustSucceed(t, res, err)
				if !slices.Equal(res.Scopes, []string{"read"}) {
					t.Errorf("Scopes = %q, want [read]", res.Scopes)
				}
			},
		},
		{
			name:      "agent identity unparseable expiry",
			resource:  authProviderResource,
			bodies:    []string{`{"success":{"token":"tok","header":"Authorization: Bearer","expireTime":"soon"}}`},
			wantCalls: 1,
			check:     wantErrContains("unparseable expireTime"),
		},
		{
			name:      "agent identity consent required",
			resource:  authProviderResource,
			bodies:    []string{`{"uriConsentRequired":{"authorizationUri":"https://consent.example","consentNonce":"n"}}`},
			wantCalls: 1,
			check:     wantConsent("https://consent.example", "n", authProviderResource),
		},
		{
			name:      "agent identity consent rejected",
			resource:  authProviderResource,
			bodies:    []string{`{"consentRejected":{}}`},
			wantCalls: 1,
			check:     wantErrIs(ErrConsentRejected),
		},
		{
			name:      "agent identity polls pending then succeeds",
			resource:  authProviderResource,
			bodies:    []string{`{"pending":{}}`, `{"success":{"token":"tok","header":"Authorization: Bearer"}}`},
			wantCalls: 2,
			check: func(t *testing.T, res *Result, err error) {
				mustSucceed(t, res, err)
				wantBearer(t, res.Credential, "tok")
			},
		},
		{
			// Fail closed: an unparsed reply must not be mistaken for "pending"
			// and polled to the timeout.
			name:      "agent identity empty result fails closed",
			resource:  authProviderResource,
			bodies:    []string{`{}`},
			wantCalls: 1,
			check:     wantErrIs(ErrUnexpectedState),
		},
		{
			name:      "agent identity multiple result arms fail closed",
			resource:  authProviderResource,
			bodies:    []string{`{"pending":{},"consentRejected":{}}`},
			wantCalls: 1,
			check:     wantErrIs(ErrUnexpectedState),
		},
		// IAM Connector: google.longrunning.Operation wrapper.
		{
			name:      "connector bearer",
			resource:  connectorResource,
			bodies:    []string{`{"done":true,"response":{"@type":"x","token":"tok","header":"Authorization: Bearer"}}`},
			wantCalls: 1,
			check: func(t *testing.T, res *Result, err error) {
				mustSucceed(t, res, err)
				wantBearer(t, res.Credential, "tok")
			},
		},
		{
			name:      "connector polls consent pending then succeeds",
			resource:  connectorResource,
			bodies:    []string{`{"metadata":{"@type":"x","consentPending":{}}}`, `{"done":true,"response":{"token":"tok","header":"Authorization: Bearer"}}`},
			wantCalls: 2,
			check: func(t *testing.T, res *Result, err error) {
				mustSucceed(t, res, err)
				wantBearer(t, res.Credential, "tok")
			},
		},
		{
			name:      "connector consent required",
			resource:  connectorResource,
			bodies:    []string{`{"metadata":{"uriConsentRequired":{"authorizationUri":"https://c.example","consentNonce":"n"}}}`},
			wantCalls: 1,
			check:     wantConsent("https://c.example", "n", connectorResource),
		},
		{
			name:      "connector consent rejected",
			resource:  connectorResource,
			bodies:    []string{`{"metadata":{"consentRejected":{}}}`},
			wantCalls: 1,
			check:     wantErrIs(ErrConsentRejected),
		},
		{
			// A rejection the client cannot parse (here the proto's original
			// snake_case spelling) must surface as unrecognized, not as a poll to
			// the timeout that reports the wrong cause.
			name:      "connector unparsed metadata fails closed",
			resource:  connectorResource,
			bodies:    []string{`{"metadata":{"consent_rejected":{}}}`},
			wantCalls: 1,
			check:     wantErrIs(ErrUnexpectedState),
		},
		{
			name:      "connector no metadata fails closed",
			resource:  connectorResource,
			bodies:    []string{`{"done":false}`},
			wantCalls: 1,
			check: func(t *testing.T, res *Result, err error) {
				wantErrIs(ErrUnexpectedState)(t, res, err)
				if !strings.Contains(err.Error(), "no status") {
					t.Errorf("error = %v, want it to name the missing status", err)
				}
			},
		},
		{
			name:      "connector multiple metadata arms fail closed",
			resource:  connectorResource,
			bodies:    []string{`{"metadata":{"consentPending":{},"consentRejected":{}}}`},
			wantCalls: 1,
			check:     wantErrIs(ErrUnexpectedState),
		},
		{
			// A credential on an operation the service did not mark done is
			// off-contract; say so rather than discard it and poll.
			name:      "connector credential without done fails closed",
			resource:  connectorResource,
			bodies:    []string{`{"response":{"token":"tok","header":"Authorization: Bearer"}}`},
			wantCalls: 1,
			check: func(t *testing.T, res *Result, err error) {
				wantErrIs(ErrUnexpectedState)(t, res, err)
				// Distinct from the no-status case below: the operator needs to
				// know a credential was present but unusable.
				if !strings.Contains(err.Error(), "did not mark done") {
					t.Errorf("error = %v, want it to name the credential-without-done shape", err)
				}
			},
		},
		{
			name:      "connector done without credential",
			resource:  connectorResource,
			bodies:    []string{`{"done":true}`},
			wantCalls: 1,
			check:     wantErrIs(ErrUnexpectedState),
		},
		{
			// A terminal status still explains a done operation with no credential.
			name:      "connector done with a rejection and no credential",
			resource:  connectorResource,
			bodies:    []string{`{"done":true,"metadata":{"consentRejected":{}}}`},
			wantCalls: 1,
			check:     wantErrIs(ErrConsentRejected),
		},
		{
			name:      "connector operation error is typed",
			resource:  connectorResource,
			bodies:    []string{`{"error":{"code":7,"message":"boom"}}`},
			wantCalls: 1,
			check: func(t *testing.T, _ *Result, err error) {
				var opErr *OperationError
				if !errors.As(err, &opErr) {
					t.Fatalf("error = %v, want *OperationError", err)
				}
				if opErr.Code != 7 {
					t.Errorf("Code = %d, want 7", opErr.Code)
				}
				if opErr.Message != "boom" {
					t.Errorf("Message = %q, want %q", opErr.Message, "boom")
				}
				if opErr.Resource != connectorResource {
					t.Errorf("Resource = %q, want %q", opErr.Resource, connectorResource)
				}
				if !strings.Contains(opErr.Service, "connector") {
					t.Errorf("Service = %q, want it to name the connector service", opErr.Service)
				}
			},
		},
		{
			name:      "connector operation error without a message",
			resource:  connectorResource,
			bodies:    []string{`{"error":{"code":3}}`},
			wantCalls: 1,
			check: func(t *testing.T, _ *Result, err error) {
				var opErr *OperationError
				if !errors.As(err, &opErr) {
					t.Fatalf("error = %v, want *OperationError", err)
				}
				if strings.Contains(err.Error(), `""`) {
					t.Errorf("error = %q, want no empty quoted message", err.Error())
				}
			},
		},
		{
			// The message is service-controlled: it must be capped and escaped the
			// same way a response body is.
			name:      "connector operation error message is escaped and capped",
			resource:  connectorResource,
			bodies:    []string{`{"error":{"code":2,"message":"boom\r\nINFO forged` + strings.Repeat("x", 2000) + `"}}`},
			wantCalls: 1,
			check: func(t *testing.T, _ *Result, err error) {
				var opErr *OperationError
				if !errors.As(err, &opErr) {
					t.Fatalf("error = %v, want *OperationError", err)
				}
				if len(opErr.Message) > maxErrorBytes+3 {
					t.Errorf("Message is %d bytes, want it truncated to %d+3", len(opErr.Message), maxErrorBytes)
				}
				if strings.Contains(err.Error(), "\r\n") {
					t.Errorf("error carries raw control bytes: %q", err.Error())
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeService(t, tc.bodies...)
			res, err := newTestClient(t, f).RetrieveCredential(t.Context(),
				Request{Resource: tc.resource, UserID: "u"})
			tc.check(t, res, err)
			if got := f.callCount(); got != tc.wantCalls {
				t.Errorf("service calls = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}

func mustSucceed(t *testing.T, res *Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("RetrieveCredential() error = %v", err)
	}
	if res == nil || res.Credential == nil {
		t.Fatalf("RetrieveCredential() = %+v, want a credential", res)
	}
}

func wantErrIs(target error) func(*testing.T, *Result, error) {
	return func(t *testing.T, _ *Result, err error) {
		t.Helper()
		if !errors.Is(err, target) {
			t.Fatalf("error = %v, want errors.Is %v", err, target)
		}
	}
}

func wantErrContains(sub string) func(*testing.T, *Result, error) {
	return func(t *testing.T, _ *Result, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Fatalf("error = %v, want it to contain %q", err, sub)
		}
	}
}

func wantConsent(authURI, nonce, key string) func(*testing.T, *Result, error) {
	return func(t *testing.T, _ *Result, err error) {
		t.Helper()
		var consent *auth.ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("error = %v, want *auth.ConsentRequiredError", err)
		}
		if consent.AuthURI != authURI {
			t.Errorf("AuthURI = %q, want %q", consent.AuthURI, authURI)
		}
		if consent.Nonce != nonce {
			t.Errorf("Nonce = %q, want %q", consent.Nonce, nonce)
		}
		// Key is what a resume layer keys the pending flow on; an empty one is
		// indistinguishable between concurrent users.
		if consent.Key != key {
			t.Errorf("Key = %q, want %q", consent.Key, key)
		}
	}
}

// TestRetrieveRoutesByResource pins that each resource shape reaches its own
// service: the two endpoints are distinct servers, so a swapped route shows up
// as the wrong host instead of passing unnoticed.
func TestRetrieveRoutesByResource(t *testing.T) {
	const okAgentIdentity = `{"success":{"token":"t","header":"Authorization: Bearer"}}`
	const okConnector = `{"done":true,"response":{"token":"t","header":"Authorization: Bearer"}}`

	tests := []struct {
		name        string
		resource    string
		wantPrefix  string
		agentBodies []string
		connBodies  []string
		wantOnAgent bool
	}{
		{"connector", connectorResource, "/v1alpha/", nil, []string{okConnector}, false},
		{"auth provider", authProviderResource, "/v1/", []string{okAgentIdentity}, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			agent := newFakeService(t, tc.agentBodies...)
			conn := newFakeService(t, tc.connBodies...)
			c := newTestClientFor(t, agent.URL, conn.URL)

			if _, err := c.RetrieveCredential(t.Context(), Request{
				Resource:          tc.resource,
				UserID:            "user-1",
				Scopes:            []string{"scope-a", "scope-b"},
				ContinueURI:       "https://example.test/continue",
				ForceRefreshToken: "stale-token",
			}); err != nil {
				t.Fatalf("RetrieveCredential() error = %v", err)
			}

			used, unused, usedURL := conn, agent, conn.URL
			if tc.wantOnAgent {
				used, unused, usedURL = agent, conn, agent.URL
			}
			if got := unused.callCount(); got != 0 {
				t.Fatalf("the other service was called %d time(s); the request went to the wrong host", got)
			}
			rec := used.recorded()
			if len(rec) != 1 {
				t.Fatalf("recorded %d requests, want 1", len(rec))
			}
			got := rec[0]

			wantHost, err := url.Parse(usedURL)
			if err != nil {
				t.Fatal(err)
			}
			if got.host != wantHost.Host {
				t.Errorf("host = %q, want %q", got.host, wantHost.Host)
			}
			if got.method != http.MethodPost {
				t.Errorf("method = %q, want POST", got.method)
			}
			if !strings.HasPrefix(got.path, tc.wantPrefix) || !strings.Contains(got.path, tc.resource) || !strings.HasSuffix(got.path, "/credentials:retrieve") {
				t.Errorf("path = %q, want prefix %q containing %q and suffix :retrieve", got.path, tc.wantPrefix, tc.resource)
			}
			if got.contentType != "application/json" || got.accept != "application/json" {
				t.Errorf("Content-Type/Accept = %q/%q, want application/json for both", got.contentType, got.accept)
			}
			if got.body.UserID != "user-1" {
				t.Errorf("body userId = %q, want %q", got.body.UserID, "user-1")
			}
			if !slices.Equal(got.body.Scopes, []string{"scope-a", "scope-b"}) {
				t.Errorf("body scopes = %q, want [scope-a scope-b]", got.body.Scopes)
			}
			// ContinueURI is what makes the 3-legged flow work, and
			// ForceRefreshToken the only way out of a stale token, so a wrong tag
			// on either would be silent and expensive.
			if got.body.ContinueURI != "https://example.test/continue" {
				t.Errorf("body continueUri = %q, want %q", got.body.ContinueURI, "https://example.test/continue")
			}
			if got.body.ForceRefreshToken != "stale-token" {
				t.Errorf("body forceRefreshToken = %q, want %q", got.body.ForceRefreshToken, "stale-token")
			}
		})
	}
}

func TestRetrieveHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := newTestClientFor(t, srv.URL, srv.URL).RetrieveCredential(t.Context(),
		Request{Resource: authProviderResource, UserID: "u"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusInternalServerError)
	}
	if !strings.Contains(apiErr.Body, "nope") {
		t.Errorf("Body = %q, want it to carry the response body", apiErr.Body)
	}
	// The error must say which of the two services answered.
	if !strings.Contains(apiErr.Service, "agent identity") {
		t.Errorf("Service = %q, want it to name the agent identity service", apiErr.Service)
	}
}

// A 3xx is not a success. The client refuses to follow it, so the redirect
// response itself must be classified as an error carrying its status.
func TestRetrieveRedirectIsAnAPIError(t *testing.T) {
	// 300 is the boundary: the success range ends at 299.
	for _, status := range []int{http.StatusMultipleChoices, http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://elsewhere.example/", status)
			}))
			defer srv.Close()
			_, err := newTestClientFor(t, srv.URL, srv.URL).RetrieveCredential(t.Context(),
				Request{Resource: authProviderResource, UserID: "u"})
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want *APIError", err)
			}
			if apiErr.StatusCode != status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, status)
			}
		})
	}
}

func TestRetrieveValidatesRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     Request
		wantSub string
	}{
		{"missing resource", Request{UserID: "u"}, "requires a Resource"},
		{"missing user id", Request{Resource: authProviderResource}, "requires a UserID"},
		{"path traversal", Request{Resource: "projects/p/../q/authProviders/a", UserID: "u"}, "invalid path segment"},
		{"single dot segment", Request{Resource: "projects/p/./authProviders/a", UserID: "u"}, "invalid path segment"},
		{"query injection", Request{Resource: "projects/p/locations/l/authProviders/a?x=1", UserID: "u"}, "invalid path segment"},
		{"fragment injection", Request{Resource: "projects/p/locations/l/authProviders/a#f", UserID: "u"}, "invalid path segment"},
		{"colon injection", Request{Resource: "projects/p/locations/l/authProviders/a:b", UserID: "u"}, "invalid path segment"},
		{"ampersand injection", Request{Resource: "projects/p/locations/l/authProviders/a&b", UserID: "u"}, "invalid path segment"},
		{"percent escape", Request{Resource: "projects/p/locations/l/authProviders/%2e%2e", UserID: "u"}, "invalid path segment"},
		{"space", Request{Resource: "projects/p/locations/l/authProviders/a b", UserID: "u"}, "invalid path segment"},
		{"empty segment from a leading slash", Request{Resource: "//evil.example.com/x", UserID: "u"}, "invalid path segment"},
		{"trailing slash", Request{Resource: connectorResource + "/", UserID: "u"}, "invalid path segment"},
		{"unknown collection", Request{Resource: "projects/p/locations/l/widgets/w", UserID: "u"}, "matches neither"},
		{"too few segments", Request{Resource: "projects/p", UserID: "u"}, "matches neither"},
	}
	// Point at a live server: a client with no endpoint fails at transport for
	// every input, which cannot tell a rejected request from an unreachable one.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	c := newTestClientFor(t, srv.URL, srv.URL)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			_, err := c.RetrieveCredential(t.Context(), tc.req)
			if err == nil {
				t.Fatalf("RetrieveCredential(%+v) = nil error, want error", tc.req)
			}
			// Assert the specific rejection, so a guard that fires for the wrong
			// reason is not mistaken for the right one.
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantSub)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("credentials service called %d time(s); a rejected request must not reach the wire", got)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		// Supply HTTPClient so the constructor skips the ADC lookup (offline test).
		c, err := NewClient(t.Context(), &Config{HTTPClient: &http.Client{}})
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		// Literals, not the constants: comparing a field to the constant that set
		// it asserts nothing about the value actually shipped.
		if c.agentIdentityURL != "https://agentidentitycredentials.googleapis.com" {
			t.Errorf("agentIdentityURL = %q", c.agentIdentityURL)
		}
		if c.connectorURL != "https://iamconnectorcredentials.googleapis.com" {
			t.Errorf("connectorURL = %q", c.connectorURL)
		}
		if c.pollTimeout != 10*time.Second {
			t.Errorf("pollTimeout = %v, want 10s", c.pollTimeout)
		}
		if c.initialBackoff != 500*time.Millisecond {
			t.Errorf("initialBackoff = %v, want 500ms", c.initialBackoff)
		}
	})
	t.Run("nil config uses defaults", func(t *testing.T) {
		fakeADC(t)
		c, err := NewClient(t.Context(), nil)
		if err != nil {
			t.Fatalf("NewClient(ctx, nil) error = %v", err)
		}
		if c.agentIdentityURL != "https://agentidentitycredentials.googleapis.com" || c.pollTimeout != 10*time.Second {
			t.Errorf("NewClient(ctx, nil) = %+v, want the documented defaults", c)
		}
	})
	t.Run("requests the cloud-platform scope", func(t *testing.T) {
		if cloudPlatformScope != "https://www.googleapis.com/auth/cloud-platform" {
			t.Errorf("cloudPlatformScope = %q", cloudPlatformScope)
		}
	})
	t.Run("trims endpoint trailing slash", func(t *testing.T) {
		c, err := NewClient(t.Context(), &Config{
			HTTPClient:            &http.Client{},
			AgentIdentityEndpoint: "https://ai.example.com/",
			ConnectorEndpoint:     "https://conn.example.com/",
		})
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		if c.agentIdentityURL != "https://ai.example.com" {
			t.Errorf("agentIdentityURL = %q, want trailing slash trimmed", c.agentIdentityURL)
		}
		if c.connectorURL != "https://conn.example.com" {
			t.Errorf("connectorURL = %q, want trailing slash trimmed", c.connectorURL)
		}
	})
	t.Run("applies a positive poll timeout", func(t *testing.T) {
		c, err := NewClient(t.Context(), &Config{HTTPClient: &http.Client{}, PollTimeout: 42 * time.Second})
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		if c.pollTimeout != 42*time.Second {
			t.Errorf("pollTimeout = %v, want 42s", c.pollTimeout)
		}
	})
	t.Run("negative poll timeout falls back to the default", func(t *testing.T) {
		c, err := NewClient(t.Context(), &Config{HTTPClient: &http.Client{}, PollTimeout: -time.Second})
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		if c.pollTimeout != 10*time.Second {
			t.Errorf("pollTimeout = %v, want the default 10s (a negative value must not mean 'never retry')", c.pollTimeout)
		}
	})
}

func TestNewClientRejectsBadEndpoint(t *testing.T) {
	tests := []struct {
		name, endpoint, wantSub string
	}{
		{"bare slash", "/", "absolute http or https"},
		{"relative", "agentidentitycredentials.googleapis.com", "absolute http or https"},
		{"no host", "https://", "no host"},
		{"unsupported scheme", "ftp://example.com", "absolute http or https"},
		{"user info", "https://user:pass@example.com", "user info"},
		{"query", "https://example.com?x=1", "query"},
		{"fragment", "https://example.com#f", "fragment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range []string{"AgentIdentityEndpoint", "ConnectorEndpoint"} {
				cfg := &Config{HTTPClient: &http.Client{}}
				if field == "AgentIdentityEndpoint" {
					cfg.AgentIdentityEndpoint = tc.endpoint
				} else {
					cfg.ConnectorEndpoint = tc.endpoint
				}
				_, err := NewClient(t.Context(), cfg)
				if err == nil {
					t.Fatalf("NewClient(%s=%q) = nil error, want a config error", field, tc.endpoint)
				}
				if !strings.Contains(err.Error(), tc.wantSub) || !strings.Contains(err.Error(), field) {
					t.Errorf("error = %v, want it to name %s and contain %q", err, field, tc.wantSub)
				}
			}
		})
	}
}

// A Client that did not come from NewClient must report that, not panic.
func TestZeroClientErrors(t *testing.T) {
	var c Client
	if _, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"}); err == nil {
		t.Fatal("zero Client returned nil error, want an error")
	}
	var nilClient *Client
	if _, err := nilClient.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"}); err == nil {
		t.Fatal("nil *Client returned nil error, want an error")
	}
}

func TestMapCredential(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		token      string
		wantBearer string
		wantAPIKey [2]string
		wantErrSub string
	}{
		{name: "authorization bearer", header: "Authorization: Bearer", token: "t", wantBearer: "t"},
		{name: "authorization bearer lowercase", header: "authorization: bearer", token: "t", wantBearer: "t"},
		{name: "authorization bearer padded", header: "Authorization:   Bearer  ", token: "t", wantBearer: "t"},
		{name: "custom header", header: "X-Goog-Api-Key", token: "k", wantAPIKey: [2]string{"X-Goog-Api-Key", "k"}},
		// A name that is NOT X-Goog-Api-Key: with the mirror deleted, the two
		// assertions in wantAPIKey would otherwise read the same header and pass.
		{name: "third-party header is mirrored", header: "X-Acme-Token", token: "k", wantAPIKey: [2]string{"X-Acme-Token", "k"}},
		{name: "bare authorization maps to an api key", header: "Authorization", token: "k", wantAPIKey: [2]string{"Authorization", "k"}},
		{name: "empty header", header: "", token: "t", wantErrSub: "empty header or token"},
		{name: "empty token", header: "Authorization: Bearer", token: "", wantErrSub: "empty header or token"},
		// A scheme that merely starts with "bearer" is a different scheme, and
		// coercing it would silently send the wrong Authorization value.
		{name: "bearer prefix is not bearer", header: "Authorization: BearerFoo", token: "t", wantErrSub: "cannot represent"},
		{name: "bearer with a suffix is not bearer", header: "Authorization: bearer-v2", token: "t", wantErrSub: "cannot represent"},
		{name: "bearer in a scheme list is not bearer", header: "Authorization: Bearer, Basic", token: "t", wantErrSub: "cannot represent"},
		// Basic is a real scheme this client cannot express; the error must name
		// the scheme rather than blame the header name.
		{name: "basic scheme is named", header: "Authorization: Basic", token: "t", wantErrSub: "cannot represent"},
		{name: "header carrying a scheme is not a usable field name", header: "X-Api-Key: Token", token: "k", wantErrSub: "not a usable HTTP header name"},
		// The token is service-controlled too: a control byte in it must be
		// rejected here, not by net/http when the caller finally uses it.
		{name: "token with CRLF", header: "X-Api-Key", token: "tok\r\nX-Evil: 1", wantErrSub: "not a usable HTTP header value"},
		{name: "token with NUL", header: "X-Api-Key", token: "tok\x00", wantErrSub: "not a usable HTTP header value"},
		{name: "token with DEL", header: "X-Api-Key", token: "tok\x7f", wantErrSub: "not a usable HTTP header value"},
		{name: "bearer token with a newline", header: "Authorization: Bearer", token: "tok\n", wantErrSub: "not a usable HTTP header value"},
		{name: "token with a tab is allowed", header: "X-Api-Key", token: "a\tb", wantAPIKey: [2]string{"X-Api-Key", "a\tb"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := mapCredential(tc.header, tc.token)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("mapCredential(%q, %q) = %#v, want an error", tc.header, tc.token, cred)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("error = %v, want it to contain %q", err, tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("mapCredential() error = %v", err)
			}
			switch {
			case tc.wantBearer != "":
				wantBearer(t, cred, tc.wantBearer)
			case tc.wantAPIKey[0] != "":
				wantAPIKey(t, cred, tc.wantAPIKey[0], tc.wantAPIKey[1])
			default:
				t.Fatalf("test case %q sets no expectation", tc.name)
			}
		})
	}
}

// Both empty-input guards must stand on their own: with only one asserted, the
// other can be deleted unnoticed.
func TestMapCredentialEmptyGuardsAreIndependent(t *testing.T) {
	if _, err := mapCredential("", "tok"); err == nil {
		t.Error(`mapCredential("", "tok") = nil error, want error`)
	}
	if _, err := mapCredential("X-Api-Key", ""); err == nil {
		t.Error(`mapCredential("X-Api-Key", "") = nil error, want error`)
	}
}

// Whatever mapCredential accepts must survive the real transport, not merely
// http.Request.Write (which silently replaces CR/LF with spaces).
func TestMapCredentialOutputSurvivesTheWire(t *testing.T) {
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	defer srv.Close()

	for _, tc := range []struct{ header, token string }{
		{"Authorization: Bearer", "tok"},
		{"X-Acme-Token", "k"},
		{"X-Api-Key", "a\tb"},
	} {
		cred, err := mapCredential(tc.header, tc.token)
		if err != nil {
			t.Fatalf("mapCredential(%q, %q) error = %v", tc.header, tc.token, err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := cred.Apply(req.Header); err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("mapCredential(%q, %q) produced headers the transport refused: %v", tc.header, tc.token, err)
		}
		_ = resp.Body.Close()
		if len(seen) == 0 {
			t.Fatalf("mapCredential(%q, %q): server saw no headers", tc.header, tc.token)
		}
	}
}

func TestRetrieveContextCanceledWhilePending(t *testing.T) {
	// One staged reply and a long backoff: cancelling must return during the
	// wait, without a second call. Without the ctx arm the call would sleep out
	// the whole backoff and then poll again.
	f := newFakeService(t, `{"pending":{}}`)
	c := newTestClient(t, f)
	c.pollTimeout = time.Minute
	c.initialBackoff = 30 * time.Second

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(20*time.Millisecond, cancel)

	start := time.Now()
	_, err := c.RetrieveCredential(ctx, Request{Resource: authProviderResource, UserID: "u"})
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RetrieveCredential() error = %v, want context.Canceled", err)
	}
	// "Promptly" is the guarantee, and it is the whole point of the select.
	if elapsed > 5*time.Second {
		t.Errorf("returned after %v, want it to abort the poll wait promptly", elapsed)
	}
	if got := f.callCount(); got != 1 {
		t.Errorf("service calls = %d, want 1; a cancelled poll must not issue another request", got)
	}
	if !strings.Contains(err.Error(), authProviderResource) {
		t.Errorf("error = %v, want it to name the resource", err)
	}
}

// A cause set by the caller must survive, not be flattened to context.Canceled.
func TestRetrieveContextCancelCausePropagates(t *testing.T) {
	f := newFakeService(t, `{"pending":{}}`)
	c := newTestClient(t, f)
	c.initialBackoff = 10 * time.Second

	sentinel := errors.New("caller gave up")
	ctx, cancel := context.WithCancelCause(t.Context())
	time.AfterFunc(20*time.Millisecond, func() { cancel(sentinel) })

	_, err := c.RetrieveCredential(ctx, Request{Resource: authProviderResource, UserID: "u"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the cancellation cause", err)
	}
}

func TestRetrievePollTimeout(t *testing.T) {
	f := newFakeService(t, `{"pending":{}}`, `{"pending":{}}`, `{"pending":{}}`)
	c := newTestClient(t, f)
	// A backoff step deliberately larger than the budget's remainder: the second
	// wait must be clamped to what is left (50ms), not run the full 300ms step.
	c.pollTimeout = 200 * time.Millisecond
	c.initialBackoff = 150 * time.Millisecond

	start := time.Now()
	_, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"})
	elapsed := time.Since(start)

	if !errors.Is(err, ErrPollTimeout) {
		t.Fatalf("RetrieveCredential() error = %v, want ErrPollTimeout", err)
	}
	if elapsed > 320*time.Millisecond {
		t.Errorf("returned after %v, want the wait clamped to the 200ms budget rather than the 300ms backoff step", elapsed)
	}
	// The attempt count is the operator's only clue about how much of the budget
	// went on retries, so pin the number rather than just the word.
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Errorf("error = %v, want it to report 3 attempts", err)
	}
	if got := f.callCount(); got != 3 {
		t.Errorf("service calls = %d, want 3", got)
	}
	if !strings.Contains(err.Error(), "attempts") {
		t.Errorf("error = %v, want it to report how many attempts were made", err)
	}
}

// PollTimeout bounds retries, not the first attempt: a slow first response must
// not consume the whole budget and leave no retry.
func TestPollTimeoutExcludesTheFirstAttempt(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			time.Sleep(120 * time.Millisecond)
			_, _ = io.WriteString(w, `{"pending":{}}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":{"token":"tok","header":"Authorization: Bearer"}}`)
	}))
	defer srv.Close()

	c := newTestClientFor(t, srv.URL, srv.URL)
	c.pollTimeout = 80 * time.Millisecond

	res, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"})
	if err != nil {
		t.Fatalf("RetrieveCredential() error = %v", err)
	}
	wantBearer(t, res.Credential, "tok")
	if got := calls.Load(); got != 2 {
		t.Errorf("service calls = %d, want 2 (a retry must still happen after a slow first attempt)", got)
	}
}

// The documented schedule (0.5, 1, 2, 4, 8s) is the service's, so pin both the
// doubling and the cap.
func TestNextBackoff(t *testing.T) {
	tests := []struct {
		in, want time.Duration
	}{
		{500 * time.Millisecond, time.Second},
		{time.Second, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{4 * time.Second, 8 * time.Second},
		{8 * time.Second, 8 * time.Second},
		{30 * time.Second, 8 * time.Second},
	}
	for _, tc := range tests {
		if got := nextBackoff(tc.in); got != tc.want {
			t.Errorf("nextBackoff(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if defaultInitialBackoff != 500*time.Millisecond {
		t.Errorf("defaultInitialBackoff = %v, want 500ms", defaultInitialBackoff)
	}
	if maxBackoff != 8*time.Second {
		t.Errorf("maxBackoff = %v, want 8s", maxBackoff)
	}
}

// The gaps between polls must actually grow: a constant delay would still pass
// every other polling test here.
func TestRetrieveBackoffGrowsBetweenPolls(t *testing.T) {
	f := newFakeService(t, `{"pending":{}}`, `{"pending":{}}`, `{"pending":{}}`,
		`{"success":{"token":"tok","header":"Authorization: Bearer"}}`)
	c := newTestClient(t, f)
	c.initialBackoff = 20 * time.Millisecond
	c.pollTimeout = 5 * time.Second

	if _, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"}); err != nil {
		t.Fatalf("RetrieveCredential() error = %v", err)
	}
	rec := f.recorded()
	if len(rec) != 4 {
		t.Fatalf("recorded %d requests, want 4", len(rec))
	}
	var gaps []time.Duration
	for i := 1; i < len(rec); i++ {
		gaps = append(gaps, rec[i].at.Sub(rec[i-1].at))
	}
	// Compare against half the expected step to stay clear of scheduler noise
	// while still failing on a flat (non-doubling) schedule.
	wantAtLeast := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}
	for i, gap := range gaps {
		if gap < wantAtLeast[i] {
			t.Errorf("gap %d = %v, want >= %v (the backoff must double; got %v)", i+1, gap, wantAtLeast[i], gaps)
		}
	}
}

// TestNewClientRefusesRedirects pins the ADC client's redirect guard.
func TestNewClientRefusesRedirects(t *testing.T) {
	fakeADC(t)

	var targetSawAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetSawAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"success":{"token":"attacker","header":"Authorization: Bearer"}}`)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	c, err := NewClient(t.Context(), &Config{
		AgentIdentityEndpoint: redirector.URL,
		ConnectorEndpoint:     redirector.URL,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	res, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("RetrieveCredential() = %#v, error %v; want the 3xx surfaced as *APIError", res, err)
	}
	if apiErr.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusTemporaryRedirect)
	}
	if targetSawAuth != "" {
		t.Errorf("redirect target received Authorization %q; the token must not leave the configured host", targetSawAuth)
	}
}

// A caller-supplied client gets the same guard. Building one the ordinary way
// (oauth2.NewClient) leaves net/http's default redirect policy in place, which
// would otherwise re-sign the request onto the redirect target and let that
// target dictate the credential this package returns.
func TestSuppliedHTTPClientRefusesRedirects(t *testing.T) {
	var targetSawAuth, targetSawBody string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetSawAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		targetSawBody = string(b)
		_, _ = io.WriteString(w, `{"success":{"token":"ATTACKER","header":"Authorization: Bearer"}}`)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	caller := oauth2.NewClient(t.Context(),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "VICTIM-TOKEN", TokenType: "Bearer"}))

	c, err := NewClient(t.Context(), &Config{
		HTTPClient:            caller,
		AgentIdentityEndpoint: redirector.URL,
		ConnectorEndpoint:     redirector.URL,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	res, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "victim@example.com"})
	if err == nil {
		t.Fatalf("RetrieveCredential() = %#v, nil error; want the 3xx surfaced as an error", res)
	}
	if targetSawAuth != "" {
		t.Errorf("redirect target received Authorization %q; the caller's token must not leave the configured host", targetSawAuth)
	}
	if targetSawBody != "" {
		t.Errorf("redirect target received the request body %q; the acting user id must not leak", targetSawBody)
	}
	if res != nil {
		t.Errorf("RetrieveCredential() = %#v; the redirect target must not dictate the credential", res)
	}
}

// The guard is applied to a copy: the caller's own client keeps its policy.
func TestSuppliedHTTPClientIsNotMutated(t *testing.T) {
	caller := &http.Client{}
	if _, err := NewClient(t.Context(), &Config{HTTPClient: caller}); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if caller.CheckRedirect != nil {
		t.Error("NewClient mutated the caller's http.Client; it must copy instead")
	}
}

// TestNewClientOutlivesConstructionCtx pins the token source's detachment from
// the construction context. Callers build the client inside a bounded,
// request-scoped context, and every token minted after that context ends must
// still authenticate.
func TestNewClientOutlivesConstructionCtx(t *testing.T) {
	fakeADC(t)
	f := newFakeService(t, `{"success":{"token":"tok","header":"Authorization: Bearer"}}`)

	ctx, cancel := context.WithCancel(t.Context())
	c, err := NewClient(ctx, &Config{AgentIdentityEndpoint: f.URL, ConnectorEndpoint: f.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	cancel()

	res, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"})
	if err != nil {
		t.Fatalf("RetrieveCredential() error = %v", err)
	}
	wantBearer(t, res.Credential, "tok")
}

// The client NewClient builds itself must bound a single request, or a stalled
// service pins the caller indefinitely: PollTimeout only caps the retry loop.
func TestADCClientHasARequestTimeout(t *testing.T) {
	fakeADC(t)
	c, err := NewClient(t.Context(), nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("ADC client Timeout = %v, want 30s", c.httpClient.Timeout)
	}
}

// fakeADC points Application Default Credentials at a local token server so the
// ADC branch of NewClient runs offline. The token expires immediately, so every
// call mints a fresh one and the token source's own context stays observable.
func fakeADC(t *testing.T) {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"ADC-TOKEN","token_type":"Bearer","expires_in":1}`)
	}))
	t.Cleanup(tokenSrv.Close)

	adc := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(adc, []byte(`{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","token_uri":"`+tokenSrv.URL+`"}`), 0o600); err != nil {
		t.Fatalf("write fake ADC: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", adc)
}

// TestDoPostOversizeKeepsStatus: an error page big enough to trip the body cap
// must still report its status, the most actionable field.
func TestDoPostOversizeKeepsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, strings.Repeat("x", maxBodyBytes+10))
	}))
	defer srv.Close()
	_, err := newTestClientFor(t, srv.URL, srv.URL).RetrieveCredential(t.Context(),
		Request{Resource: authProviderResource, UserID: "u"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusBadGateway)
	}
	// The captured body is capped at the error limit, not the read limit.
	if len(apiErr.Body) > maxErrorBytes+3 {
		t.Errorf("Body is %d bytes, want it truncated to %d+3", len(apiErr.Body), maxErrorBytes)
	}
}

// The read itself must be bounded, not merely checked after the fact: without
// io.LimitReader the client would buffer whatever a hostile service sends.
func TestDoPostBoundsTheRead(t *testing.T) {
	var read atomic.Int64
	c := newTestClientFor(t, "https://ai.example.invalid", "https://conn.example.invalid")
	c.httpClient = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       &countingReadCloser{n: &read, remaining: 16 * maxBodyBytes},
			Request:    r,
		}, nil
	})}
	if _, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"}); err == nil {
		t.Fatal("RetrieveCredential() = nil error, want the oversize response rejected")
	}
	if got := read.Load(); got > maxBodyBytes+1 {
		t.Errorf("read %d bytes from the response body, want at most %d", got, maxBodyBytes+1)
	}
}

// A non-2xx whose body cannot be read must still report the status.
func TestDoPostReadErrorKeepsStatus(t *testing.T) {
	c := newTestClientFor(t, "https://ai.example.invalid", "https://conn.example.invalid")
	c.httpClient = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     http.Header{},
			Body:       errReadCloser{},
			Request:    r,
		}, nil
	})}
	_, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusServiceUnavailable)
	}
}

// A 2xx body over the cap must be rejected, not handed to json.Unmarshal
// truncated (and thus garbled).
func TestDoPostRejectsOversizeSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"success":{"token":"t","header":"Authorization: Bearer"}}`+strings.Repeat(" ", maxBodyBytes))
	}))
	defer srv.Close()
	_, err := newTestClientFor(t, srv.URL, srv.URL).RetrieveCredential(t.Context(),
		Request{Resource: authProviderResource, UserID: "u"})
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("error = %v, want the oversize response rejected", err)
	}
}

// A body of exactly the cap is still valid: the limit rejects what is over it,
// not what reaches it.
func TestDoPostAcceptsBodyExactlyAtTheCap(t *testing.T) {
	body := `{"success":{"token":"t","header":"Authorization: Bearer"}}`
	body += strings.Repeat(" ", maxBodyBytes-len(body))
	if len(body) != maxBodyBytes {
		t.Fatalf("test setup: body is %d bytes, want %d", len(body), maxBodyBytes)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	res, err := newTestClientFor(t, srv.URL, srv.URL).RetrieveCredential(t.Context(),
		Request{Resource: authProviderResource, UserID: "u"})
	if err != nil {
		t.Fatalf("RetrieveCredential() error = %v, want a body at exactly the cap to be accepted", err)
	}
	wantBearer(t, res.Credential, "t")
}

// TestDoPostEscapesErrorBody: a service-controlled body must not be able to
// forge log lines through the returned error.
func TestDoPostEscapesErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "unavailable\r\nINFO auth: credential granted user=victim")
	}))
	defer srv.Close()
	_, err := newTestClientFor(t, srv.URL, srv.URL).RetrieveCredential(t.Context(),
		Request{Resource: authProviderResource, UserID: "u"})
	if err == nil {
		t.Fatal("RetrieveCredential() = nil error, want error")
	}
	if strings.Contains(err.Error(), "\r\n") {
		t.Errorf("error carries raw control bytes: %q", err.Error())
	}
	if !strings.Contains(err.Error(), `\r\n`) {
		t.Errorf("error = %q, want the body escaped", err.Error())
	}
}

// A decode failure must still name the service and the size it choked on.
func TestDoPostDecodeErrorIsDiagnosable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html>not json</html>`)
	}))
	defer srv.Close()
	_, err := newTestClientFor(t, srv.URL, srv.URL).RetrieveCredential(t.Context(),
		Request{Resource: authProviderResource, UserID: "u"})
	if err == nil {
		t.Fatal("RetrieveCredential() = nil error, want a decode error")
	}
	for _, want := range []string{"decode", "agent identity"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err.Error(), want)
		}
	}
}

// Transport failures keep their cause reachable with errors.Is.
func TestDoPostWrapsTransportError(t *testing.T) {
	sentinel := errors.New("dial refused")
	c := newTestClientFor(t, "https://ai.example.invalid", "https://conn.example.invalid")
	c.httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, sentinel
	})}
	_, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the transport error", err)
	}
}

func TestValidateAuthURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{name: "https", uri: "https://consent.example/x?y=1"},
		{name: "http", uri: "http://consent.example"},
		{name: "javascript", uri: "javascript:alert(1)", wantErr: true},
		{name: "data", uri: "data:text/html,<script>", wantErr: true},
		{name: "file", uri: "file:///etc/passwd", wantErr: true},
		{name: "relative", uri: "/consent", wantErr: true},
		{name: "empty", uri: "", wantErr: true},
		{name: "no host", uri: "https://", wantErr: true},
		{name: "oversize", uri: "https://consent.example/?x=" + strings.Repeat("a", maxAuthURIBytes), wantErr: true},
		// Exactly at the cap is still allowed: the bound is a limit, not a target.
		{name: "exactly at the cap", uri: padTo("https://consent.example/?x=", maxAuthURIBytes)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAuthURI(tc.uri)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateAuthURI(%.40q) error = %v, wantErr %v", tc.uri, err, tc.wantErr)
			}
			if err != nil && len(err.Error()) > 2*maxErrorBytes {
				t.Errorf("error is %d bytes; a hostile URI must not bloat it", len(err.Error()))
			}
		})
	}
}

// A hostile consent URI must be rejected rather than handed to the caller to
// show an end user.
func TestRetrieveRejectsHostileConsentURI(t *testing.T) {
	f := newFakeService(t, `{"uriConsentRequired":{"authorizationUri":"javascript:alert(1)","consentNonce":"n"}}`)
	_, err := newTestClient(t, f).RetrieveCredential(t.Context(),
		Request{Resource: authProviderResource, UserID: "u"})
	var consent *auth.ConsentRequiredError
	if errors.As(err, &consent) {
		t.Fatalf("error = %#v, want the hostile consent URI rejected", consent)
	}
	if err == nil || !strings.Contains(err.Error(), "consent URI") {
		t.Fatalf("error = %v, want it to name the consent URI", err)
	}
}

func TestTruncateForError(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "short is unchanged", in: "nope", want: "nope"},
		{name: "exactly at the cap is unchanged", in: strings.Repeat("a", maxErrorBytes), want: strings.Repeat("a", maxErrorBytes)},
		{name: "long is cut", in: strings.Repeat("a", 2000), want: strings.Repeat("a", maxErrorBytes) + "..."},
		// A body need not be UTF-8; an unbounded backup would walk to 0 here and
		// throw away every byte of diagnostic context.
		{name: "non utf8 keeps context", in: strings.Repeat("\x80", 2000), want: strings.Repeat("\x80", maxErrorBytes) + "..."},
		{
			// A rune straddling the cap is dropped whole.
			name: "straddling rune is dropped",
			in:   strings.Repeat("a", maxErrorBytes-1) + "€" + strings.Repeat("b", 2000),
			want: strings.Repeat("a", maxErrorBytes-1) + "...",
		},
		{
			// ...but only the straddling one: a complete rune before it stays.
			name: "complete rune before the cap is kept",
			in:   strings.Repeat("z", maxErrorBytes-3) + "A\x80\x80" + strings.Repeat("b", 2000),
			want: strings.Repeat("z", maxErrorBytes-3) + "A\x80\x80" + "...",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateForError(tc.in)
			if got != tc.want {
				t.Errorf("truncateForError() = %d bytes ending %q, want %d bytes ending %q",
					len(got), got[max(0, len(got)-8):], len(tc.want), tc.want[max(0, len(tc.want)-8):])
			}
			// Whatever it returns must stay a prefix of the input.
			if body := strings.TrimSuffix(got, "..."); !strings.HasPrefix(tc.in, body) {
				t.Errorf("result %q is not a prefix of the input", body)
			}
		})
	}
}

func TestValidHeaderFieldValue(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", true}, // an empty token is rejected earlier, by mapCredential
		{"plain", true},
		{"with space", true},
		{"with\ttab", true},
		{"high\xc3\xa9", true},
		{"cr\r", false},
		{"lf\n", false},
		{"nul\x00", false},
		{"del\x7f", false},
		{"vertical\vtab", false},
	}
	for _, tc := range tests {
		if got := validHeaderFieldValue(tc.in); got != tc.want {
			t.Errorf("validHeaderFieldValue(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidHeaderFieldName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"X-Api-Key", true},
		{"x-goog-api-key", true},
		{"With Space", false},
		{"With:Colon", false},
		{"With\nNewline", false},
		{"Tilde~Ok", true},
	}
	for _, tc := range tests {
		if got := validHeaderFieldName(tc.in); got != tc.want {
			t.Errorf("validHeaderFieldName(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The exported Client is documented as safe for concurrent use.
func TestClientIsSafeForConcurrentUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"success":{"token":"tok","header":"Authorization: Bearer"}}`)
	}))
	defer srv.Close()
	c := newTestClientFor(t, srv.URL, srv.URL)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.RetrieveCredential(t.Context(), Request{Resource: authProviderResource, UserID: "u"})
			if err != nil {
				t.Errorf("RetrieveCredential() error = %v", err)
				return
			}
			wantBearer(t, res.Credential, "tok")
		}()
	}
	wg.Wait()
}

// wantBearer fails t unless cred is an auth.BearerCredential carrying token.
func wantBearer(t *testing.T, cred auth.Credential, token string) {
	t.Helper()
	b, ok := cred.(auth.BearerCredential)
	if !ok {
		t.Fatalf("credential = %#v, want auth.BearerCredential", cred)
	}
	if b.Token != token {
		t.Fatalf("bearer token = %q, want %q", b.Token, token)
	}
}

// wantAPIKey fails t unless applying cred sets the named header and the
// X-Goog-Api-Key mirror (adk-python parity) to value.
func wantAPIKey(t *testing.T, cred auth.Credential, name, value string) {
	t.Helper()
	h := http.Header{}
	if err := cred.Apply(h); err != nil {
		t.Fatalf("cred.Apply() error = %v", err)
	}
	if got := h.Get(name); got != value {
		t.Errorf("header %q = %q, want %q", name, got, value)
	}
	if got := h.Get("X-Goog-Api-Key"); got != value {
		t.Errorf("X-Goog-Api-Key = %q, want %q (adk-python parity)", got, value)
	}
}

// padTo extends s with filler to exactly n bytes, for pinning a boundary at the
// limit rather than safely past it.
func padTo(s string, n int) string {
	if len(s) > n {
		panic("padTo: seed longer than the target")
	}
	return s + strings.Repeat("a", n-len(s))
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// countingReadCloser yields remaining bytes of filler and records how many were
// actually read.
type countingReadCloser struct {
	n         *atomic.Int64
	remaining int
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := min(len(p), c.remaining)
	for i := range p[:n] {
		p[i] = 'x'
	}
	c.remaining -= n
	c.n.Add(int64(n))
	return n, nil
}

func (c *countingReadCloser) Close() error { return nil }

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (errReadCloser) Close() error             { return nil }
