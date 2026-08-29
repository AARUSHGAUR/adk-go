// Copyright 2025 Google LLC
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

package adkrest_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/adk/v2/server/adkrest"
)

// TestServerRejectsUnauthenticated verifies the server enforces authentication
// when Auth is enabled (the bug was that no auth was enforced at all).
func TestServerRejectsUnauthenticated(t *testing.T) {
	srv, err := adkrest.NewServer(adkrest.ServerConfig{
		Auth: adkrest.AuthConfig{Enabled: true, Tokens: []string{"good"}},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// No token -> 401.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/apps/myapp/users/u1/sessions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	// Wrong token -> 401.
	req := httptest.NewRequest(http.MethodPost, "/apps/myapp/users/u1/sessions", nil)
	req.Header.Set("Authorization", "Bearer bad")
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", rec2.Code)
	}
}

// TestAuthMiddlewareUnit verifies a valid token is accepted (including /health
// being exempt) so callers can confirm the middleware passes authorized requests.
func TestAuthMiddlewareUnit(t *testing.T) {
	mw := adkrest.AuthMiddleware(adkrest.AuthConfig{Enabled: true, Tokens: []string{"good"}})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	h := mw(next)

	// Valid token passes.
	req := httptest.NewRequest(http.MethodGet, "/apps", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 299 {
		t.Fatalf("valid token should pass, got %d", rec.Code)
	}

	// /health is exempt from auth.
	recH := httptest.NewRecorder()
	h.ServeHTTP(recH, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recH.Code != 299 {
		t.Fatalf("/health should be exempt, got %d", recH.Code)
	}
}

// TestServerRejectsOversizedBody verifies the request-body size limit is applied
// (the bug allowed unlimited bodies -> unauthenticated memory-exhaustion DoS).
func TestServerRejectsOversizedBody(t *testing.T) {
	srv, err := adkrest.NewServer(adkrest.ServerConfig{MaxPayloadSize: 1024})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	body := make([]byte, 1<<20) // 1 MiB, exceeds the 1 KiB limit.
	req := httptest.NewRequest(http.MethodPost, "/apps/myapp/users/u1/sessions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("expected oversized body to be rejected, got 200")
	}
}
