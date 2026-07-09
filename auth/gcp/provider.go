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
	"sync"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/auth"
)

// Scheme identifies a GCP auth resource and the access it requests. It mirrors
// adk-python's GcpAuthProviderScheme.
type Scheme struct {
	// Name is the full resource name, routed by [Client]: either
	// projects/*/locations/*/connectors/* (IAM Connector) or
	// projects/*/locations/*/authProviders/* (Agent Identity).
	Name string
	// Scopes are the OAuth scopes requested for the credential.
	Scopes []string
	// ContinueURI is the developer-hosted URI used to finalize managed-OAuth
	// (3-legged) flows; unused by non-interactive flows.
	ContinueURI string
}

// ProviderOption configures a provider built by [NewProvider].
type ProviderOption func(*provider)

// WithClient sets the [Client] used to reach the credential services. When
// unset, a default client (backed by Application Default Credentials) is created
// lazily on first use.
func WithClient(c *Client) ProviderOption { return func(p *provider) { p.client = c } }

// WithStore sets the [auth.CredentialStore] used to cache resolved credentials
// across requests (keyed by app, user, and resource). When unset, an in-memory
// store is used. Caching matters here because each miss is a network round-trip
// (and up to a ~10s pending poll) to the credential service.
func WithStore(s auth.CredentialStore) ProviderOption { return func(p *provider) { p.store = s } }

// NewProvider returns an [auth.CredentialProvider] that resolves credentials for
// the given GCP resource via the Agent Identity / IAM Connector services.
//
// The acting user is taken from the ADK context ([agent.FromContext]) at resolve
// time, so the provider must run within an agent invocation (e.g. wired into
// mcptoolset or remoteagent).
func NewProvider(scheme Scheme, opts ...ProviderOption) (auth.CredentialProvider, error) {
	if scheme.Name == "" {
		return nil, fmt.Errorf("gcp: NewProvider requires a scheme Name")
	}
	p := &provider{scheme: scheme}
	for _, opt := range opts {
		opt(p)
	}
	if p.store == nil {
		p.store = auth.NewInMemoryCredentialStore()
	}
	return p, nil
}

type provider struct {
	scheme Scheme
	store  auth.CredentialStore

	mu     sync.Mutex
	client *Client
}

var (
	_ auth.CredentialProvider = (*provider)(nil)
	_ auth.RefreshingProvider = (*provider)(nil)
)

// Credential implements [auth.CredentialProvider].
func (p *provider) Credential(ctx context.Context) (*auth.Credential, error) {
	key, err := p.resolveKey(ctx)
	if err != nil {
		return nil, err
	}
	if cred, ok, err := p.store.Get(ctx, key); err == nil && ok {
		return cred, nil
	}
	return p.fetch(ctx, key, p.request(key, "", false))
}

// Refresh implements [auth.RefreshingProvider]: it discards the cached
// credential and forces the service to mint a new one, passing the prior
// (rejected) token where the service needs it.
func (p *provider) Refresh(ctx context.Context) (*auth.Credential, error) {
	key, err := p.resolveKey(ctx)
	if err != nil {
		return nil, err
	}
	var prior string
	if cred, ok, _ := p.store.Get(ctx, key); ok {
		prior = credentialToken(cred)
	}
	return p.fetch(ctx, key, p.request(key, prior, true))
}

// resolveKey builds the store key from the acting user's identity.
func (p *provider) resolveKey(ctx context.Context) (auth.CredentialKey, error) {
	rc, err := agent.RequireContext(ctx)
	if err != nil {
		return auth.CredentialKey{}, fmt.Errorf("gcp: %w", err)
	}
	userID := rc.UserID()
	if userID == "" {
		return auth.CredentialKey{}, fmt.Errorf("gcp: ADK context has no user id")
	}
	return auth.CredentialKey{AppName: rc.AppName(), UserID: userID, Key: p.scheme.Name}, nil
}

func (p *provider) request(key auth.CredentialKey, priorToken string, forceRefresh bool) Request {
	return Request{
		Resource:     p.scheme.Name,
		UserID:       key.UserID,
		Scopes:       p.scheme.Scopes,
		ContinueURI:  p.scheme.ContinueURI,
		ForceRefresh: forceRefresh,
		PriorToken:   priorToken,
	}
}

// fetch retrieves a credential and (best-effort) caches it; a store write
// failure must not fail auth.
func (p *provider) fetch(ctx context.Context, key auth.CredentialKey, req Request) (*auth.Credential, error) {
	client, err := p.resolveClient()
	if err != nil {
		return nil, err
	}
	cred, expiresAt, err := client.retrieve(ctx, req)
	if err != nil {
		return nil, err
	}
	_ = p.store.Set(ctx, key, cred, expiresAt)
	return cred, nil
}

// credentialToken returns the token string carried by a resolved GCP credential.
func credentialToken(c *auth.Credential) string {
	switch {
	case c == nil:
		return ""
	case c.HTTP != nil:
		return c.HTTP.Token
	case c.APIKey != nil:
		return c.APIKey.Value
	case c.OAuth2 != nil:
		return c.OAuth2.AccessToken
	}
	return ""
}

// resolveClient returns the configured client, creating a default one (backed by
// Application Default Credentials) on first use. A detached context is used so
// the long-lived client is not bound to a single request.
func (p *provider) resolveClient() (*Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == nil {
		c, err := NewClient(context.Background())
		if err != nil {
			return nil, err
		}
		p.client = c
	}
	return p.client, nil
}
