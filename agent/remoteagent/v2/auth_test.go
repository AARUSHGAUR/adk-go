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

package remoteagent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"golang.org/x/oauth2"

	"google.golang.org/adk/v2/auth"
	"google.golang.org/adk/v2/session"
)

func TestCredentialsServiceGet(t *testing.T) {
	tests := []struct {
		name     string
		provider auth.CredentialProvider
		want     a2aclient.AuthCredential
		wantErr  bool
	}{
		{
			name:     "static bearer token",
			provider: auth.StaticToken("tok"),
			want:     "tok",
		},
		{
			name:     "api key value",
			provider: auth.APIKey("X-Api-Key", "secret"),
			want:     "secret",
		},
		{
			name:     "oauth2 token source",
			provider: auth.TokenSourceProvider(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at"})),
			want:     "at",
		},
		{
			name: "oauth2 missing access token",
			provider: auth.ProviderFunc(func(context.Context) (*auth.Credential, error) {
				return &auth.Credential{OAuth2: &auth.OAuth2Credential{}}, nil
			}),
			wantErr: true,
		},
		{
			name: "provider error",
			provider: auth.ProviderFunc(func(context.Context) (*auth.Credential, error) {
				return nil, errors.New("boom")
			}),
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := credentialsService{provider: tc.provider}
			got, err := svc.Get(t.Context(), a2aclient.SessionID("sid"), a2a.SecuritySchemeName("scheme"))
			if tc.wantErr {
				if err == nil {
					t.Fatal("Get() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("Get() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewA2AAuthWithClientProviderIsError(t *testing.T) {
	_, err := NewA2A(A2AConfig{
		Name:           "a2a",
		AgentCard:      &a2a.AgentCard{Name: "a2a"},
		Auth:           auth.StaticToken("tok"),
		ClientProvider: NewA2AClientProvider(a2aclient.NewFactory()),
	})
	if err == nil {
		t.Fatal("NewA2A() = nil error, want error for Auth combined with a custom ClientProvider")
	}
}

func TestRemoteAgent_AuthAttachesBearerHeader(t *testing.T) {
	executor := newA2AEventReplay(t, []a2a.Event{
		a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("ok")),
	})
	inner := a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor))

	var mu sync.Mutex
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()

	// The interceptor only attaches auth when the card declares a matching
	// security requirement, so the card must carry one.
	card := &a2a.AgentCard{
		Name:                "a2a",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(srv.URL, a2a.TransportProtocolJSONRPC)},
		Capabilities:        a2a.AgentCapabilities{Streaming: true},
		SecuritySchemes: a2a.NamedSecuritySchemes{
			"bearer": a2a.HTTPAuthSecurityScheme{Scheme: "Bearer"},
		},
		SecurityRequirements: a2a.SecurityRequirementsOptions{
			{a2a.SecuritySchemeName("bearer"): a2a.SecuritySchemeScopes{}},
		},
	}

	// Auth must attach whether the card is static or resolved per-invocation.
	tests := []struct {
		name string
		cfg  A2AConfig
	}{
		{
			name: "static card",
			cfg:  A2AConfig{Name: "a2a", AgentCard: card, Auth: auth.StaticToken("secret-token")},
		},
		{
			name: "card provider",
			cfg: A2AConfig{
				Name:              "a2a",
				AgentCardProvider: func(context.Context) (*a2a.AgentCard, error) { return card, nil },
				Auth:              auth.StaticToken("secret-token"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			gotAuth = ""
			mu.Unlock()

			remoteAgent, err := NewA2A(tc.cfg)
			if err != nil {
				t.Fatalf("NewA2A() error = %v", err)
			}

			ictx := newInvocationContext(t, []*session.Event{newUserHello()})
			if _, err := runAndCollect(ictx, remoteAgent); err != nil {
				t.Fatalf("agent.Run() error = %v", err)
			}

			mu.Lock()
			defer mu.Unlock()
			if gotAuth != "Bearer secret-token" {
				t.Errorf("server saw Authorization = %q, want %q", gotAuth, "Bearer secret-token")
			}
		})
	}
}

// TestRemoteAgent_AuthFailOpenSendsUnauthenticated pins the fail-open contract:
// when the provider errors, the a2a interceptor drops auth and the request still
// goes out (unauthenticated), rather than failing the call.
func TestRemoteAgent_AuthFailOpenSendsUnauthenticated(t *testing.T) {
	executor := newA2AEventReplay(t, []a2a.Event{
		a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("ok")),
	})
	inner := a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor))

	var mu sync.Mutex
	var gotAuth string
	var sawRequest bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		sawRequest = true
		mu.Unlock()
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()

	card := &a2a.AgentCard{
		Name:                "a2a",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(srv.URL, a2a.TransportProtocolJSONRPC)},
		Capabilities:        a2a.AgentCapabilities{Streaming: true},
		SecuritySchemes: a2a.NamedSecuritySchemes{
			"bearer": a2a.HTTPAuthSecurityScheme{Scheme: "Bearer"},
		},
		SecurityRequirements: a2a.SecurityRequirementsOptions{
			{a2a.SecuritySchemeName("bearer"): a2a.SecuritySchemeScopes{}},
		},
	}
	failing := auth.ProviderFunc(func(context.Context) (*auth.Credential, error) {
		return nil, errors.New("resolve failed")
	})

	remoteAgent, err := NewA2A(A2AConfig{Name: "a2a", AgentCard: card, Auth: failing})
	if err != nil {
		t.Fatalf("NewA2A() error = %v", err)
	}

	ictx := newInvocationContext(t, []*session.Event{newUserHello()})
	if _, err := runAndCollect(ictx, remoteAgent); err != nil {
		t.Fatalf("agent.Run() error = %v; fail-open means the request should still succeed", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !sawRequest {
		t.Fatal("server never received the request")
	}
	if gotAuth != "" {
		t.Errorf("server saw Authorization = %q, want empty (fail-open, no credential)", gotAuth)
	}
}
