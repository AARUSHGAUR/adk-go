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

package adkrest

import (
	"log"
	"net/http"
	"strings"
)

// DefaultMaxPayloadSize is the default maximum request body size (10 MiB)
// applied when ServerConfig.MaxPayloadSize is not set. It mitigates
// memory-exhaustion denial of service caused by oversized request bodies.
const DefaultMaxPayloadSize int64 = 10 << 20

// AuthConfig configures authentication for the ADK REST API server.
type AuthConfig struct {
	// Enabled turns on bearer-token authentication for all routes except /health.
	Enabled bool
	// Tokens is the set of accepted bearer tokens.
	Tokens []string
}

// MaxBytesMiddleware limits the size of request bodies to maxBytes bytes.
// Requests whose body exceeds the limit fail with 413 (Payload Too Large).
func MaxBytesMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware enforces bearer-token authentication. Requests without a
// valid "Authorization: Bearer <token>" header are rejected with 401. The
// /health endpoint is excluded so deployment liveness probes keep working.
//
// When cfg.Enabled is false the middleware is a no-op; callers (e.g. NewServer
// and the web launcher) are expected to log a warning in that case, because an
// unauthenticated ADK REST server must not be exposed to untrusted networks.
func AuthMiddleware(cfg AuthConfig) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(cfg.Tokens))
	for _, t := range cfg.Tokens {
		if t != "" {
			allowed[t] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}
			const prefix = "Bearer "
			h := r.Header.Get("Authorization")
			token := strings.TrimPrefix(h, prefix)
			if !strings.HasPrefix(h, prefix) || !validToken(token, allowed) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func validToken(token string, allowed map[string]struct{}) bool {
	if token == "" {
		return false
	}
	_, ok := allowed[token]
	return ok
}

// warnNoAuth logs a warning when the server is started without authentication.
func warnNoAuth() {
	log.Printf("WARNING: adkrest server is running WITHOUT authentication; do not expose it to untrusted networks")
}
