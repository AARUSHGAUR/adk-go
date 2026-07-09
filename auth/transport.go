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

package auth

import (
	"fmt"
	"io"
	"net/http"
)

// Transport is an [http.RoundTripper] that resolves a credential per request
// via a [CredentialProvider] and applies it to the outgoing request headers.
//
// The provider receives the request context (req.Context()), which — for a
// request made during a tool call — descends from the ADK context that flowed
// into the call. The resolver runs on every request so that per-user
// credentials are never shared across users; refresh and caching are handled by
// the provider's underlying token source.
//
// If the response is an auth rejection (401/403) and the provider implements
// [RefreshingProvider], Transport refreshes the credential and retries the
// request once — provided the request body can be replayed.
type Transport struct {
	// Provider resolves the credential to apply. Required.
	Provider CredentialProvider
	// Base is the underlying RoundTripper. When nil, [http.DefaultTransport].
	Base http.RoundTripper
}

// RoundTrip implements [http.RoundTripper].
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.Provider == nil {
		return nil, fmt.Errorf("auth: Transport has no Provider")
	}

	cred, err := t.Provider.Credential(req.Context())
	if err != nil {
		return nil, fmt.Errorf("auth: resolve credential: %w", err)
	}
	resp, err := applyAndSend(base, req, req.Body, cred)
	if err != nil {
		return resp, err
	}

	// One refresh-and-retry on a downstream auth rejection, when the provider
	// supports refresh and the request body can be replayed.
	if !isAuthRejected(resp.StatusCode) {
		return resp, nil
	}
	rp, ok := t.Provider.(RefreshingProvider)
	if !ok {
		return resp, nil
	}
	body, ok := replayBody(req)
	if !ok {
		return resp, nil
	}
	fresh, err := rp.Refresh(req.Context())
	if err != nil {
		return resp, nil // refresh failed: surface the original rejection
	}
	drain(resp)
	return applyAndSend(base, req, body, fresh)
}

// applyAndSend sends a clone of req (with the given body) after applying cred,
// leaving the caller's request untouched.
func applyAndSend(base http.RoundTripper, req *http.Request, body io.ReadCloser, cred *Credential) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Body = body
	if err := cred.Apply(out.Header); err != nil {
		return nil, fmt.Errorf("auth: apply credential: %w", err)
	}
	return base.RoundTrip(out)
}

func isAuthRejected(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusForbidden
}

// replayBody returns a fresh copy of req's body for a retry. It reports false
// when the body exists but cannot be replayed (no GetBody).
func replayBody(req *http.Request) (io.ReadCloser, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return http.NoBody, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	return body, true
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

var _ http.RoundTripper = (*Transport)(nil)
