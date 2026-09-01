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

package web

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"google.golang.org/adk/v2/cmd/launcher"
)

// fakeTriggerSublauncher mounts a PubSub-style trigger endpoint that decodes the
// request body as JSON, mirroring how the Eventarc and PubSub trigger
// sublaunchers register their routes via SetupSubrouters on the base router.
type fakeTriggerSublauncher struct{}

func (f fakeTriggerSublauncher) Keyword() string                    { return "faketrigger" }
func (f fakeTriggerSublauncher) Parse(_ []string) ([]string, error) { return nil, nil }
func (f fakeTriggerSublauncher) CommandLineSyntax() string          { return "faketrigger" }
func (f fakeTriggerSublauncher) SimpleDescription() string {
	return "fake trigger sublauncher for body-limit test"
}
func (f fakeTriggerSublauncher) UserMessage(_ string, _ func(v ...any)) {}

func (f fakeTriggerSublauncher) SetupSubrouters(router *mux.Router, _ *launcher.Config) error {
	subrouter := router.PathPrefix("/api").Subrouter()
	subrouter.HandleFunc("/apps/{app_name}/trigger/pubsub", func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode request: %v", err), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}).Methods(http.MethodPost)
	return nil
}

func TestBuildRouterEnforcesBodyLimitOnSublauncherTriggerRoutes(t *testing.T) {
	sub := fakeTriggerSublauncher{}
	w := &webLauncher{
		flags:              flag.NewFlagSet("web", flag.ContinueOnError),
		config:             &webConfig{maxPayloadSize: 1024},
		sublaunchers:       []Sublauncher{sub},
		activeSublaunchers: map[string]Sublauncher{sub.Keyword(): sub},
	}

	router, err := w.buildRouter(&launcher.Config{})
	if err != nil {
		t.Fatalf("buildRouter() error = %v", err)
	}

	// A request body well under the limit decodes successfully.
	smallRec := httptest.NewRecorder()
	router.ServeHTTP(smallRec, httptest.NewRequest(http.MethodPost, "/api/apps/my-app/trigger/pubsub", strings.NewReader(`{"message":{"data":"small"}}`)))
	if smallRec.Code != http.StatusNoContent {
		t.Fatalf("small request: got status %d, want %d (%s)", smallRec.Code, http.StatusNoContent, smallRec.Body.String())
	}

	// An oversized body trips http.MaxBytesReader, which the trigger handler
	// surfaces as a 400 containing "http: request body too large". If the
	// base-router body-limit middleware is removed, this request would decode
	// successfully and return 204 instead, so this test fails on regression.
	oversized := `{"message":{"data":"` + strings.Repeat("a", 8192) + `"}}`
	oversizedRec := httptest.NewRecorder()
	router.ServeHTTP(oversizedRec, httptest.NewRequest(http.MethodPost, "/api/apps/my-app/trigger/pubsub", strings.NewReader(oversized)))
	if oversizedRec.Code != http.StatusBadRequest {
		t.Fatalf("oversized request: got status %d, want %d (%s)", oversizedRec.Code, http.StatusBadRequest, oversizedRec.Body.String())
	}
	if !strings.Contains(oversizedRec.Body.String(), "http: request body too large") {
		t.Fatalf("oversized request: got body %q, want mention of %q", oversizedRec.Body.String(), "http: request body too large")
	}
}
