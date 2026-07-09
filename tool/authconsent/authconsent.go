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

// Package authconsent defines the wire contract for ADK's interactive
// (3-legged) OAuth consent round-trip: the adk_request_credential function call
// a tool emits when it needs the end user to grant consent, and the response the
// client returns once consent is complete.
//
// It is the credential analog of [google.golang.org/adk/v2/tool/toolconfirmation]
// and, like it, is a dependency-light leaf so that session, agent, and the LLM
// flow can reference the wire types without importing the heavier auth package
// (which depends on session and would otherwise form an import cycle).
package authconsent

// FunctionCallName is the name of the function call ADK emits to ask the client
// to drive the end user through interactive (3-legged) OAuth consent. It is the
// credential analog of toolconfirmation.FunctionCallName and mirrors
// adk-python's REQUEST_EUC_FUNCTION_CALL_NAME.
//
// A client interacting with an ADK agent must:
//  1. Watch for a function call with this name; its args carry a "consentRequest"
//     ([Request]) and the wrapped "originalFunctionCall".
//  2. Send the user to Request.AuthURI to grant consent.
//  3. Reply with a FunctionResponse that has the same id and name, and whose
//     payload is a [Response].
//
// ADK then resumes the original tool call.
const FunctionCallName = "adk_request_credential"

// Request is a pending interactive consent request. It rides on
// session.EventActions.RequestedCredentials keyed by the original tool call id,
// and is surfaced to the client inside the adk_request_credential function call.
//
// Its fields mirror auth.ConsentRequiredError, the error a credential provider
// returns to trigger the flow.
type Request struct {
	// AuthURI is the URL the end user must visit to grant consent.
	AuthURI string `json:"authUri"`
	// Nonce is an opaque value echoed back to correlate the consent response.
	Nonce string `json:"nonce,omitempty"`
	// Key identifies the credential to resume under (a CredentialStore key).
	Key string `json:"key,omitempty"`
}

// Response is what the client returns after the user completes consent.
//
// For managed flows (for example GCP agent-identity) it need only signal
// completion: the provider re-resolves the credential once consent is granted,
// so Token stays empty. Token is set only when the client performed the token
// exchange itself.
type Response struct {
	// Token is an access token supplied by the client when it exchanged the
	// authorization itself; empty for managed flows.
	Token string `json:"token,omitempty"`
	// Nonce echoes Request.Nonce for correlation, when returned by the client.
	Nonce string `json:"nonce,omitempty"`
}
