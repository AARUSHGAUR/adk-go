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

// Scheme describes how a target expects a caller to authenticate. It is a
// marker interface; use one of the concrete schemes below or implement
// CustomScheme for a provider-specific extension.
//
// A Scheme is the "how to authenticate" counterpart to a resolved [Credential]
// (the "what"). Providers close over the details they need at construction, so
// schemes are informational today; they let consumers (A2A card matching, the
// GCP provider) route without changing the provider interface.
//
// Not modeled yet (deferred, not rejected): OpenID Connect discovery — see
// https://swagger.io/docs/specification/v3_0/authentication/openid-connect-discovery/
// — and OAuth2 authorization-code details, which arrive with tool-level auth.
type Scheme interface {
	isScheme()
}

// APIKeyLocation identifies where an API key is carried. Only the request
// header is supported initially.
type APIKeyLocation int

const (
	// APIKeyInHeader carries the API key in a request header.
	APIKeyInHeader APIKeyLocation = iota
)

// APIKeyScheme is a header-based API key scheme.
//
// Spec: https://swagger.io/docs/specification/v3_0/authentication/api-keys/
type APIKeyScheme struct {
	Name string
	In   APIKeyLocation
}

// HTTPScheme is an HTTP auth scheme: "bearer" or "basic". The scheme name is
// the one used in the Authorization header per RFC 7235; registered values live
// in the IANA HTTP Authentication Scheme registry.
//
// Spec: https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
type HTTPScheme struct {
	Scheme string
}

// OAuth2Scheme is an OAuth2 scheme described by its endpoints and scopes.
//
// Spec: https://swagger.io/docs/specification/v3_0/authentication/oauth2/
type OAuth2Scheme struct {
	AuthURL  string
	TokenURL string
	Scopes   []string
}

func (APIKeyScheme) isScheme() {}
func (HTTPScheme) isScheme()   {}
func (OAuth2Scheme) isScheme() {}

// CustomScheme is the extension point for provider-specific schemes (for
// example the GCP agent-identity scheme). Implementations report a stable
// SchemeType so consumers can route on it.
type CustomScheme interface {
	Scheme
	SchemeType() string
}
