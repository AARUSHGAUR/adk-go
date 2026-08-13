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

package gcp

import (
	"context"
	"fmt"
)

// agentIdentityResponse mirrors the RetrieveCredentialsResponse "result" oneof.
// JSON cannot enforce the oneof, so result counts the arms rather than trusting
// declaration order.
type agentIdentityResponse struct {
	Success            *credentialPayload `json:"success"`
	Pending            *struct{}          `json:"pending"`
	URIConsentRequired *consentDetail     `json:"uriConsentRequired"`
	ConsentRejected    *struct{}          `json:"consentRejected"`
}

// result collapses the response's "result" oneof into an outcome, erroring if
// the service returned no recognized arm, or more than one.
func (r agentIdentityResponse) result(resource string) (outcome, error) {
	set := 0
	for _, ok := range []bool{r.Success != nil, r.Pending != nil, r.URIConsentRequired != nil, r.ConsentRejected != nil} {
		if ok {
			set++
		}
	}
	if set > 1 {
		return nil, fmt.Errorf("%w: %s set %d result arms at once for %q",
			ErrUnexpectedState, agentIdentityService, set, resource)
	}
	switch {
	case r.Success != nil:
		return r.Success.outcome()
	case r.URIConsentRequired != nil:
		return consentOutcome{authURI: r.URIConsentRequired.AuthorizationURI, nonce: r.URIConsentRequired.ConsentNonce}, nil
	case r.ConsentRejected != nil:
		return rejectedOutcome{}, nil
	case r.Pending != nil:
		return pendingOutcome{}, nil
	default:
		return nil, fmt.Errorf("%w: %s returned an empty result for %q",
			ErrUnexpectedState, agentIdentityService, resource)
	}
}

// retrieveAgentIdentity calls the Agent Identity service, whose response is
// returned synchronously (no long-running-operation wrapper).
func (c *Client) retrieveAgentIdentity(ctx context.Context, req Request) (outcome, error) {
	url := fmt.Sprintf("%s/v1/%s/credentials:retrieve", c.agentIdentityURL, req.Resource)

	var out agentIdentityResponse
	if err := c.doPost(ctx, agentIdentityService, url, newRetrieveRequest(req), &out); err != nil {
		return nil, err
	}
	return out.result(req.Resource)
}
