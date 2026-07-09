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
	"encoding/json"
	"fmt"
	"iter"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/internal/utils"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/authconsent"
	"google.golang.org/adk/v2/tool/toolconfirmation"
)

type resumedCredentialCall struct {
	response *authconsent.Response
	call     genai.FunctionCall
}

// RequestCredentialRequestProcessor resumes tool calls that were paused for
// interactive (3-legged) OAuth consent. It is the credential twin of
// [RequestConfirmationRequestProcessor] and mirrors adk-python's
// auth_preprocessor: when the latest user turn carries adk_request_credential
// function responses, it matches each back to the paused tool call and re-runs
// the original tool with the consent response threaded in.
func RequestCredentialRequestProcessor(ctx agent.InvocationContext, req *model.LLMRequest, f *Flow) iter.Seq2[*session.Event, error] {
	return func(yield func(*session.Event, error) bool) {
		if asLLMAgent(ctx.Agent()) == nil {
			return
		}

		toolsmap := make(map[string]tool.Tool)
		for _, t := range f.Tools {
			toolsmap[t.Name()] = t
		}

		var events []*session.Event
		if ctx.Session() != nil {
			for e := range ctx.Session().Events().All() {
				events = append(events, e)
			}
		}

		// Collect adk_request_credential responses from the latest user turn.
		credentialResponses := make(map[string]authconsent.Response)
		credentialEventIndex := -1
		for k := len(events) - 1; k >= 0; k-- {
			event := events[k]
			if event.Author != "user" {
				continue
			}
			responses := utils.FunctionResponses(event.Content)
			if len(responses) == 0 {
				return
			}
			for _, funcResp := range responses {
				if funcResp.Name != authconsent.FunctionCallName {
					continue
				}
				cr, err := decodeCredentialResponse(funcResp, event.ID)
				if err != nil {
					yield(nil, err)
					return
				}
				credentialResponses[funcResp.ID] = cr
			}
			credentialEventIndex = k
			break
		}

		if len(credentialResponses) == 0 {
			return
		}

		for k := len(events) - 2; k >= 0; k-- {
			event := events[k]
			// Find the system-generated adk_request_credential FunctionCall event.
			calls := utils.FunctionCalls(event.Content)
			if len(calls) == 0 {
				continue
			}
			toolsToResume := map[string]*resumedCredentialCall{}
			for _, functionCall := range calls {
				response, ok := credentialResponses[functionCall.ID]
				if !ok {
					continue
				}
				originalFunctionCall, err := toolconfirmation.OriginalCallFrom(functionCall)
				if err != nil {
					continue
				}
				r := response
				toolsToResume[originalFunctionCall.ID] = &resumedCredentialCall{
					response: &r,
					call:     *originalFunctionCall,
				}
			}

			if len(toolsToResume) == 0 {
				continue
			}

			// Drop tool calls already resumed in a later event.
			for j := len(events) - 1; j > credentialEventIndex; j-- {
				responses := utils.FunctionResponses(events[j].Content)
				for _, resp := range responses {
					delete(toolsToResume, resp.ID)
				}
				if len(toolsToResume) == 0 {
					break
				}
			}
			if len(toolsToResume) == 0 {
				continue
			}

			parts := make([]*genai.Part, 0, len(toolsToResume))
			authResponses := make(map[string]*authconsent.Response, len(toolsToResume))
			for callID, rc := range toolsToResume {
				parts = append(parts, &genai.Part{FunctionCall: &rc.call})
				authResponses[callID] = rc.response
			}

			ev, err := f.handleFunctionCalls(ctx, toolsmap, &model.LLMResponse{
				Content: &genai.Content{Parts: parts, Role: genai.RoleUser},
			}, nil, authResponses, nil)
			if !yield(ev, err) {
				return
			}
		}
	}
}

// decodeCredentialResponse extracts an authconsent.Response from a client
// FunctionResponse, accepting both the ADK-web encoding (a single "response"
// JSON string) and a plain map, mirroring the confirmation decode.
func decodeCredentialResponse(funcResp *genai.FunctionResponse, eventID string) (authconsent.Response, error) {
	var cr authconsent.Response
	if funcResp.Response == nil {
		return cr, nil
	}
	if raw, ok := funcResp.Response["response"]; ok && len(funcResp.Response) == 1 {
		s, ok := raw.(string)
		if !ok {
			return cr, fmt.Errorf("credential response for event id %q: 'response' key is not a string", eventID)
		}
		if err := json.Unmarshal([]byte(s), &cr); err != nil {
			return cr, fmt.Errorf("credential response for event id %q: unmarshal 'response': %w", eventID, err)
		}
		return cr, nil
	}
	b, err := json.Marshal(funcResp.Response)
	if err != nil {
		return cr, fmt.Errorf("credential response for event id %q: marshal: %w", eventID, err)
	}
	if err := json.Unmarshal(b, &cr); err != nil {
		return cr, fmt.Errorf("credential response for event id %q: unmarshal: %w", eventID, err)
	}
	return cr, nil
}
