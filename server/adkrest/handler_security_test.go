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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/adk/v2/server/adkrest"
	"google.golang.org/adk/v2/session"
)

// TestServerRejectsOversizedBody verifies the server rejects request bodies
// larger than ServerConfig.MaxPayloadSize. It is written to fail if the
// MaxBytesMiddleware is removed from NewServer: without the limit, the body
// below is valid JSON and the request would succeed.
func TestServerRejectsOversizedBody(t *testing.T) {
	srv, err := adkrest.NewServer(adkrest.ServerConfig{
		SessionService: session.InMemoryService(),
		MaxPayloadSize: 1024,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// A valid JSON body that is far larger than the 1 KiB limit. "state" is a
	// map so the body decodes cleanly when the limit is not enforced.
	payload := fmt.Sprintf(`{"state": {"padding": %q}}`, strings.Repeat("a", 256*1024))
	req := httptest.NewRequest(http.MethodPost, "/apps/myapp/users/u1/sessions", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusBadRequest; got != want {
		t.Fatalf("oversized body status = %d, want %d", got, want)
	}
	if got, want := rec.Body.String(), "http: request body too large\n"; got != want {
		t.Fatalf("oversized body response = %q, want %q", got, want)
	}
}
