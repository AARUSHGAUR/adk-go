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

package gcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/auth"
	"google.golang.org/adk/v2/auth/gcp"
	icontext "google.golang.org/adk/v2/internal/context"
	"google.golang.org/adk/v2/platform"
	"google.golang.org/adk/v2/session"
)

const testResource = "projects/p/locations/l/authProviders/ap"

// TestProviderCredential drives two users through one shared provider: the
// provider is long-lived, so serving one user's credential to another is the
// failure that matters. It also pins scopes and continueUri on the wire.
func TestProviderCredential(t *testing.T) {
	var gotUsers []string
	var gotScopes []string
	var gotContinueURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			UserID      string   `json:"userId"`
			Scopes      []string `json:"scopes"`
			ContinueURI string   `json:"continueUri"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotUsers = append(gotUsers, body.UserID)
		gotScopes, gotContinueURI = body.Scopes, body.ContinueURI
		// Echo the caller back, so a credential served to the wrong user shows up.
		_, _ = io.WriteString(w, `{"success":{"token":"tok-`+body.UserID+`","header":"Authorization: Bearer"}}`)
	}))
	defer srv.Close()

	scopes := []string{"s1", "s2"}
	p := newProvider(t, srv, gcp.ProviderScheme{
		Name:        testResource,
		Scopes:      scopes,
		ContinueURI: "https://example.test/continue",
	})
	scopes[0] = "mutated" // the provider must have cloned this

	for _, user := range []string{"alice", "bob"} {
		cred, err := p.Credential(adkContext(t, user))
		if err != nil {
			t.Fatalf("Credential(%q) error = %v", user, err)
		}
		if bc, ok := cred.(auth.BearerCredential); !ok || bc.Token != "tok-"+user {
			t.Errorf("credential for %q = %+v, want bearer %q", user, cred, "tok-"+user)
		}
	}
	if !slices.Equal(gotUsers, []string{"alice", "bob"}) {
		t.Errorf("service saw users %q, want [alice bob]", gotUsers)
	}
	if !slices.Equal(gotScopes, []string{"s1", "s2"}) {
		t.Errorf("body scopes = %q, want [s1 s2] (caller's later mutation must not leak)", gotScopes)
	}
	if gotContinueURI != "https://example.test/continue" {
		t.Errorf("body continueUri = %q, want the scheme's", gotContinueURI)
	}
}

// TestProviderCredentialConcurrent drives two users through one shared provider
// at the same time. The sequential case above pins the wire contract; this one
// pins that concurrency cannot cross the streams.
func TestProviderCredentialConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			UserID string `json:"userId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = io.WriteString(w, `{"success":{"token":"tok-`+body.UserID+`","header":"Authorization: Bearer"}}`)
	}))
	defer srv.Close()

	p := newProvider(t, srv, gcp.ProviderScheme{Name: testResource})
	users := []string{"alice", "bob", "carol", "dave"}
	ctxs := make([]context.Context, len(users))
	for i, u := range users {
		ctxs[i] = adkContext(t, u)
	}

	var wg sync.WaitGroup
	got := make([]auth.Credential, len(users)*8)
	errs := make([]error, len(users)*8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = p.Credential(ctxs[i%len(users)])
		}()
	}
	wg.Wait()

	for i, cred := range got {
		want := "tok-" + users[i%len(users)]
		if errs[i] != nil {
			t.Fatalf("Credential(%s) error = %v", users[i%len(users)], errs[i])
		}
		if bc, ok := cred.(auth.BearerCredential); !ok || bc.Token != want {
			t.Errorf("credential %d = %+v, want bearer %q", i, cred, want)
		}
	}
}

// TestProviderErrorAttribution pins that a failed retrieval says which resource
// failed — several providers can be wired into one process — and names no
// caller-supplied id, since this text is fed to the model and persisted in the
// session. Sentinels must stay matchable through the wrap.
func TestProviderErrorAttribution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `denied`)
	}))
	defer srv.Close()

	p := newProvider(t, srv, gcp.ProviderScheme{Name: testResource})
	ctx := adkContext(t, "alice@example.test")
	id, _ := agent.IdentityFromContext(ctx)
	_, err := p.Credential(ctx)
	if err == nil {
		t.Fatal("Credential() = nil error, want the service failure")
	}
	if !strings.Contains(err.Error(), testResource) {
		t.Errorf("Credential() error = %v, want it to name the resource", err)
	}
	for _, unwanted := range []string{"alice@example.test", id.SessionID} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("Credential() error = %v, want the caller-supplied %q kept out of it", err, unwanted)
		}
	}
	var apiErr *gcp.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("Credential() error = %v, want a wrapped *gcp.APIError with status 403", err)
	}
}

// TestProviderNoActingUser covers both identity failures: the guard must reject
// before any service call, the two cases must stay distinguishable, and neither
// message may carry a caller-supplied id — this text reaches the model and is
// persisted in the session.
func TestProviderNoActingUser(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func(t *testing.T) context.Context
		wantMsg string
	}{
		{
			name:    "not an ADK context",
			ctx:     func(t *testing.T) context.Context { return t.Context() },
			wantMsg: "no ADK invocation identity",
		},
		{
			name:    "invocation without a user",
			ctx:     userlessADKContext,
			wantMsg: "carries no user",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fails the test if reached: no identity means no service call.
			srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("credentials service must not be called without an ADK identity")
			}))
			defer srv.Close()

			p := newProvider(t, srv, gcp.ProviderScheme{Name: testResource})
			_, err := p.Credential(tt.ctx(t))
			if !errors.Is(err, gcp.ErrNoActingUser) {
				t.Fatalf("Credential() error = %v, want gcp.ErrNoActingUser", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Credential() error = %v, want it to mention %q", err, tt.wantMsg)
			}
			for _, unwanted := range []string{"app", "sid"} {
				if strings.Contains(err.Error(), unwanted) {
					t.Errorf("Credential() error = %v, want the caller-supplied %q kept out of it", err, unwanted)
				}
			}
		})
	}
}

func TestNewProviderValidatesScheme(t *testing.T) {
	// Everything here is a wiring mistake, and each must fail at construction
	// rather than on every request from inside an http.RoundTripper.
	bad := []struct {
		name string
		cfg  gcp.ProviderConfig
	}{
		{"empty name", gcp.ProviderConfig{}},
		{"path traversal", cfgFor("projects/p/locations/l/authProviders/../../secret")},
		{"empty path segment", cfgFor("projects/p/locations/l/authProviders//ap")},
		{"trailing slash routes differently after normalization", cfgFor("projects/p/locations/l/connectors/c/")},
		{"not a resource name at all", cfgFor("Bearer")},
		{"unknown collection", cfgFor("projects/p/locations/l/authProvidrs/ap")},
		{"truncated", cfgFor("projects/p")},
		{"unconstructed client", gcp.ProviderConfig{Scheme: gcp.ProviderScheme{Name: testResource}, Client: &gcp.Client{}}},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := gcp.NewProvider(t.Context(), tt.cfg); err == nil {
				t.Fatal("NewProvider() = nil error, want the config rejected")
			}
		})
	}

	good := []string{
		testResource,
		"projects/p/locations/l/connectors/c",
		// Domain-scoped project ids carry a colon.
		"projects/example.com:my-project/locations/l/authProviders/ap",
	}
	for _, name := range good {
		t.Run("accepts "+name, func(t *testing.T) {
			if _, err := gcp.NewProvider(t.Context(), cfgFor(name)); err != nil {
				t.Fatalf("NewProvider(%q) error = %v", name, err)
			}
		})
	}
}

func cfgFor(name string) gcp.ProviderConfig {
	return gcp.ProviderConfig{Scheme: gcp.ProviderScheme{Name: name}}
}

// newProvider builds a provider whose client targets srv.
func newProvider(t *testing.T, srv *httptest.Server, scheme gcp.ProviderScheme) auth.CredentialProvider {
	t.Helper()
	client, err := gcp.NewClient(t.Context(), &gcp.Config{
		HTTPClient:            srv.Client(),
		AgentIdentityEndpoint: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	p, err := gcp.NewProvider(t.Context(), gcp.ProviderConfig{Scheme: scheme, Client: client})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	return p
}

// adkContext returns an ADK invocation context (recoverable via
// agent.IdentityFromContext) for the given user, under the app name "app".
func adkContext(t *testing.T, userID string) context.Context {
	t.Helper()
	return adkContextIn(t, "app", userID)
}

// adkContextIn is adkContext with the app name spelled out, for the tests that
// vary it.
func adkContextIn(t *testing.T, appName, userID string) context.Context {
	t.Helper()
	svc := session.InMemoryService()
	resp, err := svc.Create(t.Context(), &session.CreateRequest{AppName: appName, UserID: userID})
	if err != nil {
		t.Fatalf("session Create() error = %v", err)
	}
	return icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{Session: resp.Session})
}

// userlessADKContext returns an invocation whose session carries no user — the
// shape session.InMemoryService refuses to create, but that a custom session
// service can produce.
func userlessADKContext(t *testing.T) context.Context {
	t.Helper()
	return icontext.NewInvocationContext(t.Context(), icontext.InvocationContextParams{Session: userlessSession{}})
}

// userlessSession embeds a nil session.Session for the accessors the identity
// path never reaches.
type userlessSession struct{ session.Session }

func (userlessSession) ID() string      { return "sid" }
func (userlessSession) AppName() string { return "app" }
func (userlessSession) UserID() string  { return "" }

// echoServer answers every retrieval with a token naming what the request asked
// for, so a credential served from the wrong cache entry is visible in the token
// rather than only in a call count. It records each request.
type echoServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []echoRequest
}

type echoRequest struct {
	userID      string
	scopes      []string
	continueURI string
	caller      string // X-Caller-Identity, set by the identity transports below
}

// newEchoServer starts an echoServer whose tokens expire at expireTime (RFC
// 3339; empty for a response that reports no expiry).
func newEchoServer(t *testing.T, expireTime string) *echoServer {
	t.Helper()
	e := &echoServer{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			UserID      string   `json:"userId"`
			Scopes      []string `json:"scopes"`
			ContinueURI string   `json:"continueUri"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		req := echoRequest{
			userID:      body.UserID,
			scopes:      body.Scopes,
			continueURI: body.ContinueURI,
			caller:      r.Header.Get("X-Caller-Identity"),
		}
		e.mu.Lock()
		e.requests = append(e.requests, req)
		e.mu.Unlock()

		resp := map[string]any{"token": req.token(), "header": "Authorization: Bearer"}
		if expireTime != "" {
			resp["expireTime"] = expireTime
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": resp})
	}))
	t.Cleanup(e.Close)
	return e
}

// token is the token this request is answered with: everything the service was
// told, so any two requests that should not share a cache entry get different
// tokens.
func (r echoRequest) token() string {
	return "tok|" + r.caller + "|" + r.userID + "|" + strings.Join(r.scopes, "+") + "|" + r.continueURI
}

func (e *echoServer) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.requests)
}

// identityTransport stamps a caller identity on every request, standing in for
// the distinct service-account credentials a caller-supplied HTTPClient carries.
type identityTransport struct {
	base http.RoundTripper
	who  string
}

func (t identityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Caller-Identity", t.who)
	return t.base.RoundTrip(r)
}

// newSharingProvider builds a provider against e that shares store with every
// other provider built the same way. who names the caller identity its client
// authenticates as; two providers given the same who share one *Client.
func newSharingProvider(t *testing.T, e *echoServer, store auth.CredentialStore, clients map[string]*gcp.Client, who string, scheme gcp.ProviderScheme) auth.CredentialProvider {
	t.Helper()
	client, ok := clients[who]
	if !ok {
		var err error
		client, err = gcp.NewClient(t.Context(), &gcp.Config{
			HTTPClient:            &http.Client{Transport: identityTransport{base: e.Client().Transport, who: who}},
			AgentIdentityEndpoint: e.URL,
		})
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		clients[who] = client
	}
	p, err := gcp.NewProvider(t.Context(), gcp.ProviderConfig{Scheme: scheme, Client: client, Store: store})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	return p
}

func TestProviderCachesCredential(t *testing.T) {
	e := newEchoServer(t, "2999-01-01T00:00:00Z")

	// Default (in-memory) store; two resolves for the same app+user+resource.
	p := newProvider(t, e.Server, gcp.ProviderScheme{Name: testResource})
	for i := range 2 {
		if _, err := p.Credential(adkContext(t, "user-1")); err != nil {
			t.Fatalf("call %d: Credential() error = %v", i, err)
		}
	}
	if got := e.calls(); got != 1 {
		t.Errorf("service calls = %d, want 1 (second resolve should hit the cache)", got)
	}
}

// TestProviderCacheDimensions is the guard on the cache's headline property: a
// credential must never be served to a request that would not have been minted
// the same one. Each case runs two resolves that differ in exactly one thing,
// through one shared store, and requires that both reach the service and each
// gets its own token. Collapsing any single dimension of the cache key leaves
// every other test in the package green.
func TestProviderCacheDimensions(t *testing.T) {
	const res2 = "projects/p/locations/l/authProviders/other"
	// resolve names one call: which caller identity mints, for which end user,
	// under which app, for which scheme.
	type resolve struct {
		who, app, user string
		scheme         gcp.ProviderScheme
	}
	base := resolve{who: "sa-alpha", app: "app", user: "user-1", scheme: gcp.ProviderScheme{Name: testResource, Scopes: []string{"drive"}}}
	with := func(f func(*resolve)) resolve {
		r := base
		r.scheme.Scopes = slices.Clone(base.scheme.Scopes)
		f(&r)
		return r
	}

	tests := []struct {
		name          string
		first, second resolve
	}{
		{name: "end user", second: with(func(r *resolve) { r.user = "user-2" })},
		{name: "app", second: with(func(r *resolve) { r.app = "other-app" })},
		{name: "caller identity", second: with(func(r *resolve) { r.who = "sa-beta" })},
		{name: "resource", second: with(func(r *resolve) { r.scheme.Name = res2 })},
		{name: "scopes", second: with(func(r *resolve) { r.scheme.Scopes = []string{"drive.readonly"} })},
		{name: "continue URI", second: with(func(r *resolve) { r.scheme.ContinueURI = "https://example.com/finish" })},
		// The two pairs below are what an encoding that joins the components on a
		// delimiter collides, since neither "," nor "|" is escaped or barred from a
		// scope or a URI: both members slot alike under
		// name + "|" + join(scopes, ",") + "|" + continueURI.
		{
			name:   "one scope holding the scope separator",
			first:  with(func(r *resolve) { r.scheme.Scopes = []string{"a,b"} }),
			second: with(func(r *resolve) { r.scheme.Scopes = []string{"a", "b"} }),
		},
		{
			name:   "field separator shifted between scope and continue URI",
			first:  with(func(r *resolve) { r.scheme.Scopes, r.scheme.ContinueURI = []string{"x"}, "y|z" }),
			second: with(func(r *resolve) { r.scheme.Scopes, r.scheme.ContinueURI = []string{"x|y"}, "z" }),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.first
			if first.who == "" {
				first = base
			}
			// The pair is symmetric, so also run it reversed: broad-then-narrow hands
			// out more authority than was asked for, narrow-then-broad only produces a
			// confusing failure, and one pass checks only one of the two orders.
			for _, order := range [][2]resolve{{first, tc.second}, {tc.second, first}} {
				e := newEchoServer(t, "2999-01-01T00:00:00Z")
				store := auth.NewInMemoryCredentialStore()
				clients := map[string]*gcp.Client{}
				for _, r := range order {
					p := newSharingProvider(t, e, store, clients, r.who, r.scheme)
					cred, err := p.Credential(adkContextIn(t, r.app, r.user))
					if err != nil {
						t.Fatalf("Credential() error = %v", err)
					}
					want := echoRequest{userID: r.user, scopes: r.scheme.Scopes, continueURI: r.scheme.ContinueURI, caller: r.who}.token()
					if bc, ok := cred.(auth.BearerCredential); !ok || bc.Token != want {
						t.Errorf("%+v was served %+v, want bearer %q", r, cred, want)
					}
				}
				if got := e.calls(); got != 2 {
					t.Errorf("service calls = %d, want 2 (the second resolve must not reuse the first entry)", got)
				}
			}
		})
	}
}

// The same resolve twice through a shared store is one call, so the isolation
// above is not just the cache never hitting at all.
func TestProviderCacheHitsAcrossProviders(t *testing.T) {
	e := newEchoServer(t, "2999-01-01T00:00:00Z")
	store := auth.NewInMemoryCredentialStore()
	clients := map[string]*gcp.Client{}
	scheme := gcp.ProviderScheme{Name: testResource, Scopes: []string{"drive"}}
	for range 2 {
		p := newSharingProvider(t, e, store, clients, "sa-alpha", scheme)
		if _, err := p.Credential(adkContext(t, "user-1")); err != nil {
			t.Fatalf("Credential() error = %v", err)
		}
	}
	if got := e.calls(); got != 1 {
		t.Errorf("service calls = %d, want 1 (a second provider with the same client and scheme should hit the entry)", got)
	}
}

// Scope order is the caller's, not a cache dimension.
func TestProviderCacheIgnoresScopeOrder(t *testing.T) {
	e := newEchoServer(t, "2999-01-01T00:00:00Z")
	store := auth.NewInMemoryCredentialStore()
	clients := map[string]*gcp.Client{}
	for _, scopes := range [][]string{{"a", "b"}, {"b", "a"}} {
		p := newSharingProvider(t, e, store, clients, "sa-alpha", gcp.ProviderScheme{Name: testResource, Scopes: scopes})
		if _, err := p.Credential(adkContext(t, "user-1")); err != nil {
			t.Fatalf("Credential() error = %v", err)
		}
	}
	if got := e.calls(); got != 1 {
		t.Errorf("service calls = %d, want 1 (reordered scopes are the same credential)", got)
	}
}

// recordingStore reports every call and what it was handed, and can fail writes.
type recordingStore struct {
	inner   auth.CredentialStore
	sets    int
	gets    int
	setErr  error
	nilOnce bool // return a hit carrying no credential on the first Get

	lastKey     auth.CredentialKey
	lastExpires time.Time
}

func (s *recordingStore) Get(ctx context.Context, key auth.CredentialKey) (auth.Credential, bool, error) {
	s.gets++
	if s.nilOnce {
		s.nilOnce = false
		return nil, true, nil
	}
	return s.inner.Get(ctx, key)
}

func (s *recordingStore) Set(ctx context.Context, key auth.CredentialKey, cred auth.Credential, expiresAt time.Time) error {
	s.sets++
	s.lastKey, s.lastExpires = key, expiresAt
	if s.setErr != nil {
		return s.setErr
	}
	return s.inner.Set(ctx, key, cred, expiresAt)
}

func (s *recordingStore) Delete(ctx context.Context, key auth.CredentialKey) error {
	return s.inner.Delete(ctx, key)
}

// newStoreProvider builds a provider against e backed by a recordingStore.
func newStoreProvider(t *testing.T, e *echoServer, store auth.CredentialStore) auth.CredentialProvider {
	t.Helper()
	client, err := gcp.NewClient(t.Context(), &gcp.Config{HTTPClient: e.Client(), AgentIdentityEndpoint: e.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	p, err := gcp.NewProvider(t.Context(), gcp.ProviderConfig{
		Scheme: gcp.ProviderScheme{Name: testResource},
		Client: client,
		Store:  store,
	})
	if err != nil {
		t.Fatalf("NewProvider() error = %v", err)
	}
	return p
}

// A configured store is actually used, a write failure does not fail auth, and
// a hit carrying no credential is treated as a miss rather than returned.
func TestProviderStorePlumbing(t *testing.T) {
	e := newEchoServer(t, "2999-01-01T00:00:00Z")
	store := &recordingStore{inner: auth.NewInMemoryCredentialStore(), setErr: errors.New("disk on fire"), nilOnce: true}
	p := newStoreProvider(t, e, store)

	cred, err := p.Credential(adkContext(t, "user-1"))
	if err != nil {
		t.Fatalf("Credential() error = %v; a store write failure must not fail auth", err)
	}
	if cred == nil {
		t.Fatal("Credential() = nil credential; a hit with no credential must be treated as a miss")
	}
	if store.gets != 1 || store.sets != 1 {
		t.Errorf("store gets/sets = %d/%d, want 1/1 (the configured store must be used)", store.gets, store.sets)
	}
}

// TestProviderCachedExpiry pins what lifetime the provider is willing to cache
// for. The store is asked directly rather than inferred from a call count, so
// each case fails loudly if the provider stops calling Set at all.
func TestProviderCachedExpiry(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		expireTime string    // what the service reports
		want       time.Time // zero means: must not be cached
	}{
		{"honored as reported", "2030-01-01T00:05:00Z", now.Add(5 * time.Minute)},
		{"clamped to the cap", "9999-12-31T23:59:59Z", now.Add(maxCachedLifetimeForTest)},
		{"absent", "", time.Time{}},
		{"already past", "2029-12-31T23:00:00Z", time.Time{}},
		{"unparseable", "not-a-time", time.Time{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEchoServer(t, tc.expireTime)
			store := &recordingStore{inner: auth.NewInMemoryCredentialStore()}
			p := newStoreProvider(t, e, store)

			ctx := platform.WithTimeProvider(adkContext(t, "user-1"), func() time.Time { return now })
			if _, err := p.Credential(ctx); err != nil {
				t.Fatalf("Credential() error = %v", err)
			}
			switch {
			case tc.want.IsZero():
				if store.sets != 0 {
					t.Errorf("store Set called with expiry %s, want no cache write for expireTime %q", store.lastExpires, tc.expireTime)
				}
			case store.sets != 1:
				t.Errorf("store Set calls = %d, want 1", store.sets)
			case !store.lastExpires.Equal(tc.want):
				t.Errorf("cached until %s, want %s", store.lastExpires, tc.want)
			}
		})
	}
}

// maxCachedLifetimeForTest mirrors the provider's cap. Duplicated rather than
// exported: the cap is a policy the test should notice changing.
const maxCachedLifetimeForTest = time.Hour
