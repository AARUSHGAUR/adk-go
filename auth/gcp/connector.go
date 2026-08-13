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

// connectorOperation is the google.longrunning.Operation wrapper the IAM
// Connector service returns. The service does not implement true LROs, so the
// terminal result is read inline from response/metadata. The Any-typed
// response/metadata carry an extra "@type" field that is ignored here.
type connectorOperation struct {
	Done     bool                `json:"done"`
	Response *credentialPayload  `json:"response"`
	Metadata *connectorMetadata  `json:"metadata"`
	Error    *connectorErrStatus `json:"error"`
}

// connectorMetadata is the RetrieveCredentialsMetadata "status" oneof. JSON
// cannot enforce the oneof, so outcome counts the arms rather than trusting
// declaration order.
type connectorMetadata struct {
	ConsentPending     *struct{}      `json:"consentPending"`
	URIConsentRequired *consentDetail `json:"uriConsentRequired"`
	ConsentRejected    *struct{}      `json:"consentRejected"`
}

type connectorErrStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// outcome maps the status oneof, returning a nil outcome when no arm is set so
// the caller can decide what an absent status means in context.
func (m *connectorMetadata) outcome(resource string) (outcome, error) {
	if m == nil {
		return nil, nil
	}
	set := 0
	for _, ok := range []bool{m.ConsentPending != nil, m.URIConsentRequired != nil, m.ConsentRejected != nil} {
		if ok {
			set++
		}
	}
	if set > 1 {
		return nil, fmt.Errorf("%w: %s set %d metadata status arms at once for %q",
			ErrUnexpectedState, connectorService, set, resource)
	}
	switch {
	case m.URIConsentRequired != nil:
		return consentOutcome{authURI: m.URIConsentRequired.AuthorizationURI, nonce: m.URIConsentRequired.ConsentNonce}, nil
	case m.ConsentRejected != nil:
		return rejectedOutcome{}, nil
	case m.ConsentPending != nil:
		return pendingOutcome{}, nil
	}
	return nil, nil
}

// result collapses the Operation-wrapped response into an outcome.
//
// Every shape the service does not document maps to an error rather than to
// "pending". Treating an unrecognized reply as pending turns a terminal state
// the client failed to parse — a rejected consent, or an arm added after this
// code was written — into a silent poll to the timeout, reported as the wrong
// cause.
func (o connectorOperation) result(resource string) (outcome, error) {
	if o.Error != nil {
		return nil, &OperationError{
			Service:  connectorService,
			Resource: resource,
			Code:     o.Error.Code,
			Message:  truncateForError(o.Error.Message),
		}
	}
	status, err := o.Metadata.outcome(resource)
	if err != nil {
		return nil, err
	}
	if o.Done {
		if o.Response != nil {
			return o.Response.outcome()
		}
		// A terminal operation must carry a credential. When it does not, a
		// terminal status arm at least explains why; pending never does.
		if _, isPending := status.(pendingOutcome); status != nil && !isPending {
			return status, nil
		}
		return nil, fmt.Errorf("%w: %s completed the operation without a credential for %q",
			ErrUnexpectedState, connectorService, resource)
	}
	if status != nil {
		return status, nil
	}
	if o.Response != nil {
		return nil, fmt.Errorf("%w: %s returned a credential on an operation it did not mark done, for %q",
			ErrUnexpectedState, connectorService, resource)
	}
	return nil, fmt.Errorf("%w: %s reported no status on an incomplete operation for %q",
		ErrUnexpectedState, connectorService, resource)
}

// retrieveConnector calls the IAM Connector service and normalizes its
// Operation-wrapped response.
func (c *Client) retrieveConnector(ctx context.Context, req Request) (outcome, error) {
	url := fmt.Sprintf("%s/v1alpha/%s/credentials:retrieve", c.connectorURL, req.Resource)

	var op connectorOperation
	if err := c.doPost(ctx, connectorService, url, retrieveRequest{UserID: req.UserID, Scopes: req.Scopes, ContinueURI: req.ContinueURI}, &op); err != nil {
		return nil, err
	}
	return op.result(req.Resource)
}
