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

package llminternal_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/genai"
	"google.golang.org/protobuf/testing/protocmp"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/internal/llminternal"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/authconsent"
)

const mockCredentialFunctionCallID = "mock_credential_function_call_id"

// mockCredentialTool proceeds only once an interactive consent response is
// present, mirroring how a real tool re-resolves its credential after consent.
type mockCredentialTool struct{ name string }

func (m *mockCredentialTool) Name() string        { return m.name }
func (m *mockCredentialTool) Description() string { return "mock credential tool" }
func (m *mockCredentialTool) IsLongRunning() bool { return false }
func (m *mockCredentialTool) Declaration() *genai.FunctionDeclaration {
	return &genai.FunctionDeclaration{Name: m.name}
}

func (m *mockCredentialTool) Run(ctx agent.Context, args any) (map[string]any, error) {
	resp := ctx.AuthResponse()
	if resp == nil {
		return map[string]any{"error": "credential required"}, nil
	}
	return map[string]any{"result": "authorized: " + resp.Token}, nil
}

func newMockCredentialAgent() (agent.Agent, []tool.Tool, error) {
	tools := []tool.Tool{&mockCredentialTool{name: mockToolName}}
	agnt, err := llmagent.New(llmagent.Config{
		Name:  "testAgent",
		Model: &testModel{},
		Tools: tools,
	})
	return agnt, tools, err
}

func TestRequestCredentialRequestProcessor(t *testing.T) {
	originalFunctionCall := &genai.FunctionCall{
		Name: mockToolName,
		Args: map[string]any{"param1": "test"},
		ID:   mockFunctionCallID,
	}
	originalCallMap := map[string]any{
		"name": originalFunctionCall.Name,
		"args": originalFunctionCall.Args,
		"id":   originalFunctionCall.ID,
	}

	// createCredentialEvents builds the paused adk_request_credential call plus
	// the user's consent response carrying token.
	createCredentialEvents := func(token string) []*session.Event {
		reqArgs := map[string]any{
			"originalFunctionCall": originalCallMap,
			"consentRequest":       authconsent.Request{AuthURI: "https://consent.example", Key: "k1"},
		}
		respJSON, _ := json.Marshal(authconsent.Response{Token: token})
		return []*session.Event{
			{
				Author: "agent",
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{
						Parts: []*genai.Part{
							{
								FunctionCall: &genai.FunctionCall{
									Name: authconsent.FunctionCallName,
									Args: reqArgs,
									ID:   mockCredentialFunctionCallID,
								},
							},
						},
					},
				},
			},
			{
				Author: "user",
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{
						Parts: []*genai.Part{
							{
								FunctionResponse: &genai.FunctionResponse{
									Name: authconsent.FunctionCallName,
									ID:   mockCredentialFunctionCallID,
									// ADK web wraps the payload in a single "response" string key.
									Response: map[string]any{"response": string(respJSON)},
								},
							},
						},
					},
				},
			},
		}
	}

	tests := []struct {
		name       string
		events     []*session.Event
		wantEvents []*session.Event
	}{
		{name: "NoEvents", events: nil, wantEvents: nil},
		{
			name: "NoFunctionResponses",
			events: []*session.Event{
				{Author: "user", LLMResponse: model.LLMResponse{Content: &genai.Content{}}},
			},
			wantEvents: nil,
		},
		{
			name: "NonCredentialFunctionResponse",
			events: []*session.Event{
				{
					Author: "user",
					LLMResponse: model.LLMResponse{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{FunctionResponse: &genai.FunctionResponse{Name: "other_function", Response: map[string]any{}}},
							},
						},
					},
				},
			},
			wantEvents: nil,
		},
		{
			name:   "Success",
			events: createCredentialEvents("tok-123"),
			wantEvents: []*session.Event{
				{
					Author: "testAgent",
					LLMResponse: model.LLMResponse{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{
									FunctionResponse: &genai.FunctionResponse{
										Name:     mockToolName,
										ID:       mockFunctionCallID,
										Response: map[string]any{"result": "authorized: tok-123"},
									},
								},
							},
							Role: "user",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agnt, tools, err := newMockCredentialAgent()
			if err != nil {
				t.Fatalf("error creating mock llmagent: %v", err)
			}

			invocationContext := createInvocationContext(t, agnt, &fakeSession{events: tt.events})

			iter := llminternal.RequestCredentialRequestProcessor(invocationContext, &model.LLMRequest{}, &llminternal.Flow{Tools: tools})

			var gotEvents []*session.Event
			for event, err := range iter {
				if err != nil {
					t.Fatalf("RequestCredentialRequestProcessor() unexpected error: %v", err)
				}
				gotEvents = append(gotEvents, event)
			}

			if len(gotEvents) != len(tt.wantEvents) {
				t.Errorf("RequestCredentialRequestProcessor() got %d events, want %d", len(gotEvents), len(tt.wantEvents))
				return
			}

			if len(tt.wantEvents) > 0 {
				ignoreFields := []cmp.Option{
					protocmp.Transform(),
					cmpopts.IgnoreFields(session.Event{}, "ID", "Timestamp", "InvocationID"),
					cmpopts.IgnoreFields(session.EventActions{}, "StateDelta", "ArtifactDelta"),
				}
				if diff := cmp.Diff(tt.wantEvents, gotEvents, ignoreFields...); diff != "" {
					t.Errorf("RequestCredentialRequestProcessor() event diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}
