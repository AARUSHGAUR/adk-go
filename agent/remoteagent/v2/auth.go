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

package remoteagent

import (
	"context"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"

	"google.golang.org/adk/v2/auth"
)

// credentialsService adapts an [auth.CredentialProvider] to
// [a2aclient.CredentialsService]. The a2a AuthInterceptor calls Get and places
// the returned value per the agent card's security scheme (it adds the "Bearer "
// prefix or the API-key header itself), so Get returns the raw secret.
//
// The provider is not scheme-aware; it yields the same credential for whichever
// scheme the card lists first, which covers the common single-scheme case.
type credentialsService struct {
	provider auth.CredentialProvider
}

var _ a2aclient.CredentialsService = credentialsService{}

// Get implements [a2aclient.CredentialsService].
func (s credentialsService) Get(ctx context.Context, _ a2aclient.SessionID, _ a2a.SecuritySchemeName) (a2aclient.AuthCredential, error) {
	cred, err := s.provider.Credential(ctx)
	if err != nil {
		return "", err
	}
	value, err := credentialValue(cred)
	if err != nil {
		return "", err
	}
	return a2aclient.AuthCredential(value), nil
}

// credentialValue returns the raw secret the a2a AuthInterceptor transmits: the
// API-key value, the bearer token, or a freshly minted OAuth2 access token.
func credentialValue(c auth.Credential) (string, error) {
	switch v := c.(type) {
	case nil:
		return "", fmt.Errorf("remoteagent: nil credential")
	case auth.APIKeyCredential:
		return v.Value, nil
	case auth.BearerCredential:
		if v.Token == "" {
			return "", fmt.Errorf("remoteagent: a2a auth requires a bearer token credential")
		}
		return v.Token, nil
	case auth.OAuth2Credential:
		if v.TokenSource == nil {
			return "", fmt.Errorf("remoteagent: oauth2 credential missing token source")
		}
		tok, err := v.TokenSource.Token()
		if err != nil {
			return "", fmt.Errorf("remoteagent: mint oauth2 token: %w", err)
		}
		return tok.AccessToken, nil
	default:
		return "", fmt.Errorf("remoteagent: unsupported credential kind %T for a2a auth; want APIKeyCredential, BearerCredential, or OAuth2Credential", c)
	}
}
