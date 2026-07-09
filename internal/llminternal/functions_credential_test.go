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

package llminternal

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/genai"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool/authconsent"
)

func TestGenerateRequestCredentialEvent(t *testing.T) {
	originalCall := &genai.FunctionCall{
		ID:   "call_1",
		Name: "test_tool",
		Args: map[string]any{"arg": "val"},
	}

	tests := []struct {
		name                  string
		invocationContext     agent.InvocationContext
		functionCallEvent     *session.Event
		functionResponseEvent *session.Event
		wantEvent             *session.Event
	}{
		{
			name:              "no credential requested",
			invocationContext: &mockInvocationContext{invocationID: "inv_1", agentName: "agent_1"},
			functionCallEvent: &session.Event{
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{Parts: []*genai.Part{{FunctionCall: originalCall}}},
				},
			},
			functionResponseEvent: &session.Event{
				Actions: session.EventActions{RequestedCredentials: nil},
			},
			wantEvent: nil,
		},
		{
			name:              "credential requested but no matching function call",
			invocationContext: &mockInvocationContext{invocationID: "inv_1", agentName: "agent_1"},
			functionCallEvent: &session.Event{
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{ID: "other_call"}}}},
				},
			},
			functionResponseEvent: &session.Event{
				Actions: session.EventActions{
					RequestedCredentials: map[string]authconsent.Request{
						"call_1": {AuthURI: "https://consent.example"},
					},
				},
			},
			wantEvent: nil,
		},
		{
			name:              "credential requested and matching function call",
			invocationContext: &mockInvocationContext{invocationID: "inv_1", agentName: "agent_1", branch: "main"},
			functionCallEvent: &session.Event{
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{Parts: []*genai.Part{{FunctionCall: originalCall}}},
				},
			},
			functionResponseEvent: &session.Event{
				Actions: session.EventActions{
					RequestedCredentials: map[string]authconsent.Request{
						"call_1": {AuthURI: "https://consent.example", Nonce: "n1", Key: "k1"},
					},
				},
			},
			wantEvent: &session.Event{
				InvocationID: "inv_1",
				Author:       "agent_1",
				Branch:       "main",
				Actions:      session.EventActions{StateDelta: map[string]any{}, ArtifactDelta: map[string]int64{}},
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{
						Role: genai.RoleModel,
						Parts: []*genai.Part{
							{
								FunctionCall: &genai.FunctionCall{
									Name: authconsent.FunctionCallName,
									Args: map[string]any{
										"originalFunctionCall": originalCall,
										"consentRequest":       authconsent.Request{AuthURI: "https://consent.example", Nonce: "n1", Key: "k1"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateRequestCredentialEvent(tt.invocationContext, tt.functionCallEvent, tt.functionResponseEvent)

			if diff := cmp.Diff(tt.wantEvent, got,
				cmpopts.IgnoreFields(session.Event{}, "Timestamp", "LongRunningToolIDs", "ID"),
				cmpopts.IgnoreFields(genai.FunctionCall{}, "ID"),
			); diff != "" {
				t.Errorf("generateRequestCredentialEvent() mismatch (-want +got):\n%s", diff)
			}

			// The emitted consent call must be marked long-running with a non-empty id.
			if got != nil {
				if len(got.LongRunningToolIDs) != 1 || got.LongRunningToolIDs[0] == "" {
					t.Errorf("LongRunningToolIDs = %v, want one non-empty id", got.LongRunningToolIDs)
				}
			}
		})
	}
}
