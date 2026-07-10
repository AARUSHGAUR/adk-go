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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// Credential is a resolved credential ready to be applied to an outbound HTTP
// request. Exactly one of its fields is set.
type Credential struct {
	APIKey *APIKeyCredential
	HTTP   *HTTPCredential
	OAuth2 *OAuth2Credential
}

// APIKeyCredential is a header-based API key, e.g. {Name: "X-Api-Key"}.
type APIKeyCredential struct {
	Name  string
	Value string
}

// HTTPCredential is an HTTP "bearer" or "basic" credential, plus any extra
// headers to attach alongside it.
type HTTPCredential struct {
	// Scheme is "bearer" or "basic". Empty is treated as "bearer".
	Scheme string
	// Token is the bearer token (Scheme == "bearer").
	Token string
	// Username and Password are the basic credentials (Scheme == "basic").
	Username string
	Password string
	// AdditionalHeaders are set verbatim on the request.
	AdditionalHeaders map[string]string
}

// OAuth2Credential carries an OAuth2 access token. When TokenSource is set, the
// access token is minted (and auto-refreshed) at apply time; otherwise the
// static AccessToken is used. AuthURI and Nonce are populated only while
// interactive consent is pending, before any token exists.
type OAuth2Credential struct {
	AccessToken string
	TokenSource oauth2.TokenSource

	AuthURI string
	Nonce   string
}

// Apply writes the credential's headers onto h. It returns an error if the
// credential is nil, empty, has more than one kind set, or cannot produce a
// usable value (for example an OAuth2 credential still awaiting consent).
func (c *Credential) Apply(h http.Header) error {
	if c == nil {
		return fmt.Errorf("auth: nil credential")
	}

	set := 0
	if c.APIKey != nil {
		set++
	}
	if c.HTTP != nil {
		set++
	}
	if c.OAuth2 != nil {
		set++
	}
	switch {
	case set == 0:
		return fmt.Errorf("auth: empty credential")
	case set > 1:
		return fmt.Errorf("auth: credential has multiple kinds set")
	case c.APIKey != nil:
		return c.APIKey.apply(h)
	case c.HTTP != nil:
		return c.HTTP.apply(h)
	default:
		return c.OAuth2.apply(h)
	}
}

func (c *APIKeyCredential) apply(h http.Header) error {
	if c.Name == "" {
		return fmt.Errorf("auth: api key credential missing header name")
	}
	h.Set(c.Name, c.Value)
	return nil
}

func (c *HTTPCredential) apply(h http.Header) error {
	switch strings.ToLower(c.Scheme) {
	case "", "bearer":
		if c.Token == "" {
			return fmt.Errorf("auth: bearer credential missing token")
		}
		h.Set("Authorization", "Bearer "+c.Token)
	case "basic":
		// RFC 7617 allows an empty username or password alone; reject only ":".
		if c.Username == "" && c.Password == "" {
			return fmt.Errorf("auth: basic credential missing username and password")
		}
		raw := base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password))
		h.Set("Authorization", "Basic "+raw)
	default:
		return fmt.Errorf("auth: unsupported http scheme %q", c.Scheme)
	}
	for k, v := range c.AdditionalHeaders {
		h.Set(k, v)
	}
	return nil
}

func (c *OAuth2Credential) apply(h http.Header) error {
	if c.TokenSource != nil {
		tok, err := c.TokenSource.Token()
		if err != nil {
			return fmt.Errorf("auth: mint oauth2 token: %w", err)
		}
		h.Set("Authorization", tok.Type()+" "+tok.AccessToken)
		return nil
	}
	if c.AccessToken == "" {
		if c.AuthURI != "" {
			return fmt.Errorf("auth: oauth2 consent pending, no access token yet")
		}
		return fmt.Errorf("auth: oauth2 credential missing access token")
	}
	h.Set("Authorization", "Bearer "+c.AccessToken)
	return nil
}
