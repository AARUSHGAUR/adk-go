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

package mcptoolset

import (
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"google.golang.org/adk/v2/auth"
)

const testEndpoint = "https://mcp.example/mcp"

func TestBuildTransportAuthWithEndpoint(t *testing.T) {
	tr, err := buildTransport(Config{Endpoint: testEndpoint, Auth: auth.StaticToken("tok")})
	if err != nil {
		t.Fatalf("buildTransport() error = %v", err)
	}
	st, ok := tr.(*mcp.StreamableClientTransport)
	if !ok {
		t.Fatalf("transport = %T, want *mcp.StreamableClientTransport", tr)
	}
	if st.Endpoint != testEndpoint {
		t.Errorf("Endpoint = %q, want %q", st.Endpoint, testEndpoint)
	}
	if st.HTTPClient == nil {
		t.Fatal("HTTPClient = nil, want a client carrying the auth transport")
	}
	if _, ok := st.HTTPClient.Transport.(*auth.Transport); !ok {
		t.Errorf("HTTPClient.Transport = %T, want *auth.Transport", st.HTTPClient.Transport)
	}
}

func TestBuildTransportAuthWrapsStreamableTransport(t *testing.T) {
	base := &http.Client{Timeout: 7 * time.Second}
	caller := &mcp.StreamableClientTransport{
		Endpoint:             testEndpoint,
		HTTPClient:           base,
		MaxRetries:           9,
		DisableStandaloneSSE: true,
	}

	tr, err := buildTransport(Config{Transport: caller, Auth: auth.StaticToken("tok")})
	if err != nil {
		t.Fatalf("buildTransport() error = %v", err)
	}
	st, ok := tr.(*mcp.StreamableClientTransport)
	if !ok {
		t.Fatalf("transport = %T, want *mcp.StreamableClientTransport", tr)
	}

	// Non-auth fields are preserved on the copy.
	if st.Endpoint != testEndpoint || st.MaxRetries != 9 || !st.DisableStandaloneSSE {
		t.Errorf("preserved fields lost: %+v", st)
	}
	if _, ok := st.HTTPClient.Transport.(*auth.Transport); !ok {
		t.Errorf("HTTPClient.Transport = %T, want *auth.Transport", st.HTTPClient.Transport)
	}
	if st.HTTPClient.Timeout != 7*time.Second {
		t.Errorf("client Timeout = %v, want 7s (base settings should be copied)", st.HTTPClient.Timeout)
	}

	// The caller's transport and client must not be mutated.
	if st == caller {
		t.Error("caller transport was not copied")
	}
	if st.HTTPClient == base {
		t.Error("caller HTTPClient was not copied")
	}
	if caller.HTTPClient != base {
		t.Error("caller.HTTPClient was reassigned")
	}
	if base.Transport != nil {
		t.Error("caller's base client Transport was mutated")
	}
}

func TestBuildTransportAuthRejectsNonStreamable(t *testing.T) {
	_, err := buildTransport(Config{Transport: &mcp.CommandTransport{}, Auth: auth.StaticToken("tok")})
	if err == nil {
		t.Fatal("buildTransport() = nil error, want error for Auth with a non-streamable transport")
	}
}

func TestBuildTransportAuthRequiresTransport(t *testing.T) {
	_, err := buildTransport(Config{Auth: auth.StaticToken("tok")})
	if err == nil {
		t.Fatal("buildTransport() = nil error, want error for Auth without Endpoint or Transport")
	}
}

func TestBuildTransportEndpointWithoutAuth(t *testing.T) {
	tr, err := buildTransport(Config{Endpoint: testEndpoint})
	if err != nil {
		t.Fatalf("buildTransport() error = %v", err)
	}
	st, ok := tr.(*mcp.StreamableClientTransport)
	if !ok {
		t.Fatalf("transport = %T, want *mcp.StreamableClientTransport", tr)
	}
	if st.Endpoint != testEndpoint {
		t.Errorf("Endpoint = %q, want %q", st.Endpoint, testEndpoint)
	}
	if st.HTTPClient != nil {
		t.Errorf("HTTPClient = %v, want nil without Auth", st.HTTPClient)
	}
}

func TestBuildTransportPassthrough(t *testing.T) {
	caller := &mcp.CommandTransport{}
	tr, err := buildTransport(Config{Transport: caller})
	if err != nil {
		t.Fatalf("buildTransport() error = %v", err)
	}
	got, ok := tr.(*mcp.CommandTransport)
	if !ok || got != caller {
		t.Errorf("transport = %v, want the caller's transport unchanged", tr)
	}
}
