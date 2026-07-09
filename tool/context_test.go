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

package tool_test

import (
	"testing"

	"google.golang.org/adk/v2/agent"
	icontext "google.golang.org/adk/v2/internal/context"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool/authconsent"
)

func TestNewToolContext_Interfaces(t *testing.T) {
	inv := icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{})
	toolCtx := agent.NewToolContext(inv, "fn1", &session.EventActions{}, nil)

	if _, ok := toolCtx.(agent.ReadonlyContext); !ok {
		t.Errorf("tool context (%+T) is unexpectedly not a ReadonlyContext", toolCtx)
	}
}

func TestNewToolContext_RequestConfirmation_SetsSkipSummarization(t *testing.T) {
	inv := icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{})
	actions := &session.EventActions{}
	toolCtx := agent.NewToolContext(inv, "fn1", actions, nil)

	err := toolCtx.RequestConfirmation("please confirm", map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("RequestConfirmation returned unexpected error: %v", err)
	}

	if !actions.SkipSummarization {
		t.Error("RequestConfirmation did not set SkipSummarization to true")
	}

	if actions.RequestedToolConfirmations == nil {
		t.Fatal("RequestConfirmation did not set RequestedToolConfirmations")
	}
	tc, ok := actions.RequestedToolConfirmations["fn1"]
	if !ok {
		t.Fatal("RequestConfirmation did not set confirmation for function call ID 'fn1'")
	}
	if tc.Hint != "please confirm" {
		t.Errorf("expected hint 'please confirm', got %q", tc.Hint)
	}
	if tc.Confirmed {
		t.Error("expected Confirmed to be false")
	}
}

func TestNewToolContext_RequestConfirmation_AutoGeneratesIDWhenEmpty(t *testing.T) {
	inv := icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{})
	actions := &session.EventActions{}
	// NewToolContext auto-generates a UUID when functionCallID is empty.
	toolCtx := agent.NewToolContext(inv, "", actions, nil)

	err := toolCtx.RequestConfirmation("hint", nil)
	if err != nil {
		t.Fatalf("RequestConfirmation returned unexpected error: %v", err)
	}

	if !actions.SkipSummarization {
		t.Error("SkipSummarization should be set even with auto-generated function call ID")
	}
	if len(actions.RequestedToolConfirmations) != 1 {
		t.Fatalf("expected 1 confirmation entry, got %d", len(actions.RequestedToolConfirmations))
	}
	for _, tc := range actions.RequestedToolConfirmations {
		if tc.Hint != "hint" {
			t.Errorf("expected hint 'hint', got %q", tc.Hint)
		}
		if tc.Confirmed {
			t.Error("expected Confirmed to be false")
		}
	}
}

func TestNewToolContext_RequestCredential_SetsSkipSummarization(t *testing.T) {
	inv := icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{})
	actions := &session.EventActions{}
	toolCtx := agent.NewToolContext(inv, "fn1", actions, nil)

	req := authconsent.Request{AuthURI: "https://consent.example", Nonce: "n1", Key: "k1"}
	if err := toolCtx.RequestCredential(req); err != nil {
		t.Fatalf("RequestCredential returned unexpected error: %v", err)
	}

	if !actions.SkipSummarization {
		t.Error("RequestCredential did not set SkipSummarization to true")
	}
	got, ok := actions.RequestedCredentials["fn1"]
	if !ok {
		t.Fatal("RequestCredential did not set RequestedCredentials for function call ID 'fn1'")
	}
	if got != req {
		t.Errorf("RequestedCredentials[fn1] = %+v, want %+v", got, req)
	}
}

func TestNewToolContext_AuthResponse_ThreadedViaDelta(t *testing.T) {
	inv := icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{})
	toolCtx := agent.NewToolContext(inv, "fn1", &session.EventActions{}, nil)

	// A fresh tool context has no consent response.
	if got := toolCtx.AuthResponse(); got != nil {
		t.Errorf("AuthResponse() on fresh context = %+v, want nil", got)
	}

	// The resume path threads the response via WithDelta.
	resp := &authconsent.Response{Token: "tok-123"}
	resumed := toolCtx.WithDelta(&agent.CommonContextDelta{CredentialResponse: resp})
	if got := resumed.AuthResponse(); got != resp {
		t.Errorf("AuthResponse() after WithDelta = %+v, want %+v", got, resp)
	}
	// Threading must not leak back into the original context.
	if got := toolCtx.AuthResponse(); got != nil {
		t.Errorf("AuthResponse() on original context after WithDelta = %+v, want nil", got)
	}
}
