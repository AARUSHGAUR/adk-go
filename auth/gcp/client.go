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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"google.golang.org/adk/v2/auth"
)

const (
	cloudPlatformScope      = "https://www.googleapis.com/auth/cloud-platform"
	defaultAgentIdentityURL = "https://agentidentitycredentials.googleapis.com"
	defaultConnectorURL     = "https://iamconnectorcredentials.googleapis.com"

	agentIdentityService = "agent identity credentials service"
	connectorService     = "IAM connector credentials service"

	defaultPollTimeout = 10 * time.Second
	// The credentials services document an exponential polling backoff
	// (0.5, 1, 2, 4, 8s); these constants track it. The 8s step is reached only
	// when a caller raises PollTimeout above the default, whose budget runs out
	// during the 4s step.
	defaultInitialBackoff = 500 * time.Millisecond
	maxBackoff            = 8 * time.Second
	// defaultRequestTimeout bounds a single HTTP call made by the client
	// NewClient builds itself, so a stalled service cannot pin a caller forever.
	// It matches the services' own 30s RPC deadline, so it fires only when a
	// request hangs rather than cutting a slow answer short.
	defaultRequestTimeout = 30 * time.Second

	// maxBodyBytes caps a response body. Both services answer with a handful of
	// fields; anything larger is a proxy error page or a misbehaving service.
	maxBodyBytes = 1 << 20
	// maxErrorBytes caps service-controlled text echoed into an error.
	maxErrorBytes = 1024
	// maxAuthURIBytes bounds the consent URI handed back to the caller. Real
	// consent URIs carry a few query parameters; anything vastly larger is not a
	// URL a human can visit.
	maxAuthURIBytes = 8192
)

// A resource name is matched against the two services' URL path templates, so a
// name that belongs to neither is rejected instead of being interpolated into a
// request URL or silently routed to the wrong service.
var (
	connectorResourceRE    = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/connectors/[^/]+$`)
	authProviderResourceRE = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/authProviders/[^/]+$`)
	// resourceSegmentRE bounds one path segment to the characters GCP resource
	// names use. Applied per segment, so it also pins how many segments there
	// are, leaving no way to add a segment, query or fragment to the URL.
	resourceSegmentRE = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

// Sentinel errors from [Client.RetrieveCredential]; callers test with errors.Is.
var (
	// ErrConsentRejected means the end user rejected the consent request.
	ErrConsentRejected = errors.New("gcp: user consent rejected")
	// ErrPollTimeout means polling exceeded the poll timeout while the credential
	// was still pending.
	ErrPollTimeout = errors.New("gcp: timed out waiting for credentials")
	// ErrUnexpectedState means a service reported a state this client does not
	// recognize. It is returned rather than polling on, so wire drift surfaces as
	// itself instead of as a timeout.
	ErrUnexpectedState = errors.New("gcp: credentials service returned an unrecognized state")
)

// APIError is returned when a credential service responds with a non-2xx
// status. Callers match it with errors.As to tell a fatal status (say 403) from
// a transient one (503) without matching on the message.
type APIError struct {
	// Service names which of the two credential services answered.
	Service string
	// StatusCode is the HTTP status code of the response.
	StatusCode int
	// Body is the response body, truncated to 1 KiB, and empty if it could not be
	// read. It is service-controlled and unescaped, and a GCP error body echoes
	// request fields such as the user id: render it with %q, never raw.
	Body string
}

func (e *APIError) Error() string {
	// %q, not %s: the body is service-controlled and can carry control bytes
	// that would otherwise forge lines in an operator's log.
	return fmt.Sprintf("gcp: %s returned status %d: %q", e.Service, e.StatusCode, e.Body)
}

// OperationError is returned when the IAM Connector reports a failed operation.
// That failure arrives inside an HTTP 200, so it never becomes an [APIError];
// callers reach the canonical google.rpc code with errors.As.
type OperationError struct {
	// Service names which of the two credential services answered.
	Service string
	// Resource is the resource the credential was requested for.
	Resource string
	// Code is the canonical google.rpc.Code. Zero means the service reported no
	// code, not success.
	Code int
	// Message is the service's message, truncated to 1 KiB. Service-controlled;
	// treat it like [APIError.Body].
	Message string
}

func (e *OperationError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("gcp: %s reported a failed operation for %q (code %d)", e.Service, e.Resource, e.Code)
	}
	return fmt.Sprintf("gcp: %s reported a failed operation for %q (code %d): %q", e.Service, e.Resource, e.Code, e.Message)
}

// Client retrieves end-user credentials from the Agent Identity / IAM Connector
// credential services and maps them to [auth.Credential].
//
// A Client is safe for concurrent use by multiple goroutines, and is meant to be
// built once and shared: each Client caches its own access token, so building
// one per request re-reads Application Default Credentials and mints a fresh
// token every time. The zero Client is not usable; call [NewClient].
type Client struct {
	httpClient       *http.Client
	agentIdentityURL string
	connectorURL     string
	pollTimeout      time.Duration
	initialBackoff   time.Duration
}

// Config configures a [Client]. A nil *Config, or any zero-valued field, uses
// the corresponding default.
type Config struct {
	// HTTPClient calls the credential services. If nil, [NewClient] builds one
	// from Application Default Credentials (cloud-platform scope) with a 30s
	// per-request timeout. If set, it must carry its own credentials, and ADC is
	// not applied; NewClient drives a shallow copy of it that refuses redirects,
	// leaving the caller's own client untouched. The copy shares the caller's
	// Transport and Timeout, so bounding a single request stays the caller's job.
	HTTPClient *http.Client
	// AgentIdentityEndpoint overrides the Agent Identity base URL. It must be an
	// absolute http or https URL carrying no query, fragment or user info; a path
	// is kept as a prefix. Defaults to
	// https://agentidentitycredentials.googleapis.com.
	AgentIdentityEndpoint string
	// ConnectorEndpoint overrides the IAM Connector base URL, under the same rules
	// as AgentIdentityEndpoint. Defaults to
	// https://iamconnectorcredentials.googleapis.com.
	ConnectorEndpoint string
	// PollTimeout bounds the wall-clock time spent retrying after the service
	// first reports a pending state. It excludes the initial attempt, and it caps
	// the retry loop rather than any single request, so the last retry can start
	// just inside the deadline and finish after it. Bound one stalled request
	// with ctx instead. A negative value is treated as unset. Defaults to 10s.
	PollTimeout time.Duration
}

// refuseRedirect is the redirect policy for every client this package drives.
//
// A credentials:retrieve call has no reason to redirect, and following one leaks
// credentials in both directions: oauth2.Transport re-signs every hop below the
// layer where net/http strips credentials on a cross-host redirect, so the
// caller's access token would reach the redirect target, and that target's reply
// would become the credential this package hands back.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// NewClient builds a Client from cfg; a nil cfg (or any zero field) uses
// defaults. Unless cfg.HTTPClient is set, it discovers Application Default
// Credentials (cloud-platform scope) to authenticate calls to the services.
//
// ctx is used only for the duration of this call, to discover credentials. It
// does not bound the returned Client: the token source is detached from ctx's
// cancellation and deadline, so a Client built inside a request-scoped context
// keeps refreshing its token after that request ends.
//
// Either way the resulting client refuses redirects; see [refuseRedirect].
func NewClient(ctx context.Context, cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	c := &Client{
		pollTimeout:    defaultPollTimeout,
		initialBackoff: defaultInitialBackoff,
	}
	var err error
	if c.agentIdentityURL, err = endpointOrDefault(cfg.AgentIdentityEndpoint, defaultAgentIdentityURL); err != nil {
		return nil, fmt.Errorf("gcp: Config.AgentIdentityEndpoint: %w", err)
	}
	if c.connectorURL, err = endpointOrDefault(cfg.ConnectorEndpoint, defaultConnectorURL); err != nil {
		return nil, fmt.Errorf("gcp: Config.ConnectorEndpoint: %w", err)
	}
	if cfg.PollTimeout > 0 {
		c.pollTimeout = cfg.PollTimeout
	}

	if cfg.HTTPClient != nil {
		// Copy rather than mutate: the caller's client is commonly shared process
		// wide, and changing its redirect policy would reach far outside this
		// package.
		hc := *cfg.HTTPClient
		hc.CheckRedirect = refuseRedirect
		c.httpClient = &hc
		return c, nil
	}

	// The token source captures this context and reuses it for every later
	// refresh, so it must outlive the call; discovery itself needs no
	// cancellation (its only network probe bounds itself).
	detached := context.WithoutCancel(ctx)
	creds, err := google.FindDefaultCredentials(detached, cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: find default credentials: %w", err)
	}
	// oauth2.NewClient reads ctx only to pick a base transport, but its own doc
	// disclaims any lifetime past ctx; pass the detached one so the guarantee
	// above does not rest on that implementation detail.
	hc := oauth2.NewClient(detached, creds.TokenSource)
	hc.CheckRedirect = refuseRedirect
	hc.Timeout = defaultRequestTimeout
	c.httpClient = hc
	return c, nil
}

// endpointOrDefault validates a caller-supplied base URL, falling back to def
// when it is unset. A bad endpoint is rejected here rather than deferred to an
// opaque transport error at request time.
func endpointOrDefault(endpoint, def string) (string, error) {
	if endpoint == "" {
		return def, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", endpoint, err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", fmt.Errorf("%q must be an absolute http or https URL", endpoint)
	case u.Host == "":
		return "", fmt.Errorf("%q has no host", endpoint)
	case u.User != nil:
		return "", fmt.Errorf("%q must not carry user info", endpoint)
	case u.RawQuery != "" || u.ForceQuery:
		return "", fmt.Errorf("%q must not carry a query", endpoint)
	case u.Fragment != "":
		return "", fmt.Errorf("%q must not carry a fragment", endpoint)
	}
	return strings.TrimRight(endpoint, "/"), nil
}

// Request identifies the resource and acting user for a credential retrieval.
type Request struct {
	// Resource is a full resource name, either
	// projects/*/locations/*/connectors/*, routed to the IAM Connector service,
	// or projects/*/locations/*/authProviders/*, routed to Agent Identity.
	// Required.
	Resource string
	// UserID is the acting end user's identity. Required.
	UserID string
	// Scopes are the OAuth scopes requested for the credential. The service may
	// grant fewer; compare against [Result.Scopes].
	Scopes []string
	// ContinueURI is the developer-hosted URI the end user returns to once consent
	// completes. The services require it for the 3-legged OAuth flow and ignore it
	// otherwise, so a retrieval that reaches consent without one cannot be
	// finalized.
	ContinueURI string
	// ForceRefreshToken asks the service to replace a token that turned out to be
	// expired or invalid, refreshing it or starting a new consent flow. Set it
	// only after a downstream call rejected a credential, to the full token string
	// that was rejected.
	ForceRefreshToken string
}

// Result is a credential retrieved for an end user, together with the metadata
// the service returned alongside it.
type Result struct {
	// Credential applies the retrieved token to an outbound request.
	Credential auth.Credential
	// Scopes are the scopes actually granted, which can be narrower than those
	// requested: an end user may refuse some, and an authorization server may
	// return a different set. Callers must check that everything they need is
	// present. Empty if the service did not say.
	Scopes []string
	// Expiry is when the token stops working, or the zero time if the service did
	// not say. It is an upper bound: the token can be revoked earlier, and clock
	// skew between the service and this process can retire it sooner still.
	Expiry time.Time
}

// RetrieveCredential retrieves a credential for req, polling while the service
// reports a non-interactive pending state (up to the configured poll timeout).
// If interactive consent is required it returns an [auth.ConsentRequiredError].
func (c *Client) RetrieveCredential(ctx context.Context, req Request) (*Result, error) {
	if c == nil || c.httpClient == nil {
		return nil, errors.New("gcp: Client must be built by NewClient")
	}
	retrieve, err := c.route(req)
	if err != nil {
		return nil, err
	}

	// The deadline covers retries only, so a slow first attempt cannot spend the
	// whole budget before a single retry happens. It is armed on the first pending
	// reply.
	var deadline time.Time
	backoff := c.initialBackoff
	for attempt := 1; ; attempt++ {
		res, err := retrieve(ctx, req)
		if err != nil {
			return nil, err
		}
		switch o := res.(type) {
		case credOutcome:
			cred, err := mapCredential(o.header, o.token)
			if err != nil {
				return nil, err
			}
			return &Result{Credential: cred, Scopes: o.scopes, Expiry: o.expiry}, nil
		case consentOutcome:
			if err := validateAuthURI(o.authURI); err != nil {
				return nil, err
			}
			return nil, &auth.ConsentRequiredError{AuthURI: o.authURI, Nonce: o.nonce, Key: req.Resource}
		case rejectedOutcome:
			return nil, fmt.Errorf("%w for %q", ErrConsentRejected, req.Resource)
		case pendingOutcome:
			if deadline.IsZero() {
				deadline = time.Now().Add(c.pollTimeout)
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, fmt.Errorf("%w for %q after %d attempts within %v",
					ErrPollTimeout, req.Resource, attempt, c.pollTimeout)
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("gcp: retrieving credentials for %q: %w", req.Resource, context.Cause(ctx))
			case <-time.After(min(backoff, remaining)):
			}
			backoff = nextBackoff(backoff)
		default:
			return nil, fmt.Errorf("gcp: unexpected retrieval outcome %T", res)
		}
	}
}

// route validates req and picks the service its resource belongs to. A name
// matching neither service's path template is rejected rather than defaulting to
// one of them, which would reach the wrong host and report an opaque 404.
func (c *Client) route(req Request) (func(context.Context, Request) (outcome, error), error) {
	if req.Resource == "" {
		return nil, errors.New("gcp: RetrieveCredential requires a Resource")
	}
	if req.UserID == "" {
		return nil, errors.New("gcp: RetrieveCredential requires a UserID")
	}
	for _, seg := range strings.Split(req.Resource, "/") {
		if !resourceSegmentRE.MatchString(seg) || seg == "." || seg == ".." {
			return nil, fmt.Errorf("gcp: RetrieveCredential resource %q has an invalid path segment %q",
				truncateForError(req.Resource), truncateForError(seg))
		}
	}
	switch {
	case connectorResourceRE.MatchString(req.Resource):
		return c.retrieveConnector, nil
	case authProviderResourceRE.MatchString(req.Resource):
		return c.retrieveAgentIdentity, nil
	default:
		return nil, fmt.Errorf("gcp: RetrieveCredential resource %q matches neither "+
			"projects/*/locations/*/connectors/* nor projects/*/locations/*/authProviders/*",
			truncateForError(req.Resource))
	}
}

// nextBackoff advances the polling delay along the schedule both services
// document (0.5, 1, 2, 4, 8s).
func nextBackoff(cur time.Duration) time.Duration { return min(cur*2, maxBackoff) }

// validateAuthURI rejects a consent URI a caller could not safely show an end
// user. The service controls this string and the flow is for a human to visit
// it, so a javascript: or data: scheme, or an unbounded blob, is a service
// defect that must not be passed on.
func validateAuthURI(authURI string) error {
	if len(authURI) > maxAuthURIBytes {
		return fmt.Errorf("gcp: credentials service returned a %d byte consent URI, over the %d byte limit",
			len(authURI), maxAuthURIBytes)
	}
	u, err := url.Parse(authURI)
	if err != nil {
		return fmt.Errorf("gcp: credentials service returned an unparseable consent URI %q: %w",
			truncateForError(authURI), err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("gcp: credentials service returned a consent URI that is not an absolute http(s) URL: %q",
			truncateForError(authURI))
	}
	return nil
}

// outcome is the normalized result of one retrieval attempt — a closed sum type
// (one arm per state) that RetrieveCredential type-switches on.
type outcome interface{ isOutcome() }

type (
	// credOutcome carries a successfully retrieved credential and its metadata.
	credOutcome struct {
		header, token string
		scopes        []string
		expiry        time.Time
	}
	// pendingOutcome means retrieval is still pending; poll again.
	pendingOutcome struct{}
	// consentOutcome means interactive consent is required at authURI.
	consentOutcome struct {
		authURI string
		nonce   string
	}
	// rejectedOutcome means the end user rejected consent.
	rejectedOutcome struct{}
)

func (credOutcome) isOutcome()     {}
func (pendingOutcome) isOutcome()  {}
func (consentOutcome) isOutcome()  {}
func (rejectedOutcome) isOutcome() {}

// credentialPayload is the success shape shared by both services (under
// "success" for Agent Identity, "response" for the IAM Connector operation).
type credentialPayload struct {
	Token      string   `json:"token"`
	Header     string   `json:"header"`
	Scopes     []string `json:"scopes"`
	ExpireTime string   `json:"expireTime"`
}

// outcome converts the payload, reporting an expiry the service sent but this
// client cannot read rather than quietly returning a credential without one.
func (p credentialPayload) outcome() (outcome, error) {
	o := credOutcome{header: p.Header, token: p.Token, scopes: p.Scopes}
	if p.ExpireTime != "" {
		t, err := time.Parse(time.RFC3339, p.ExpireTime)
		if err != nil {
			return nil, fmt.Errorf("gcp: credentials service returned an unparseable expireTime %q: %w",
				truncateForError(p.ExpireTime), err)
		}
		o.expiry = t
	}
	return o, nil
}

// consentDetail is the shared uri-consent payload across both services.
type consentDetail struct {
	AuthorizationURI string `json:"authorizationUri"`
	ConsentNonce     string `json:"consentNonce"`
}

// retrieveRequest is the JSON body for both services' credentials:retrieve RPC.
// The auth provider / connector is bound to the URL path, not the body.
type retrieveRequest struct {
	UserID            string   `json:"userId"`
	Scopes            []string `json:"scopes,omitempty"`
	ContinueURI       string   `json:"continueUri,omitempty"`
	ForceRefreshToken string   `json:"forceRefreshToken,omitempty"`
}

func newRetrieveRequest(req Request) retrieveRequest {
	return retrieveRequest{
		UserID:            req.UserID,
		Scopes:            req.Scopes,
		ContinueURI:       req.ContinueURI,
		ForceRefreshToken: req.ForceRefreshToken,
	}
}

// mapCredential maps the service's {header, token} tuple to an [auth.Credential]:
// an "Authorization: Bearer" header becomes a bearer credential, and any other
// header name a header-based API key that also mirrors the token into
// X-Goog-Api-Key. It errors on an empty pair, on an Authorization header naming a
// scheme this client cannot represent, and on a header name or token value that
// is not usable in an HTTP request.
func mapCredential(header, token string) (auth.Credential, error) {
	if header == "" || token == "" {
		return nil, errors.New("gcp: credentials service returned an empty header or token")
	}
	// Both halves are service-controlled and both are written onto the caller's
	// outbound requests, so both are checked here. Otherwise net/http accepts the
	// credential and aborts the eventual request instead, naming whichever header
	// it reached first rather than the cause.
	if !validHeaderFieldValue(token) {
		return nil, errors.New("gcp: credentials service returned a token that is not a usable HTTP header value")
	}
	name, scheme, hasScheme := strings.Cut(header, ":")
	if strings.EqualFold(strings.TrimSpace(name), "authorization") {
		if strings.EqualFold(strings.TrimSpace(scheme), "bearer") {
			return auth.BearerCredential{Token: token}, nil
		}
		if hasScheme {
			return nil, fmt.Errorf("gcp: credentials service returned Authorization scheme %q, which this client cannot represent",
				truncateForError(strings.TrimSpace(scheme)))
		}
	}
	// Non-bearer header -> header-based API key. Matches adk-python: key by the
	// full returned header, and mirror the token into X-Goog-Api-Key too.
	if !validHeaderFieldName(header) {
		return nil, fmt.Errorf("gcp: credentials service returned %q, which is not a usable HTTP header name",
			truncateForError(header))
	}
	key := auth.APIKeyCredential{Name: header, Value: token}
	return auth.WithHeaders(key, map[string]string{"X-Goog-Api-Key": token}), nil
}

// doPost sends body as JSON to url and decodes a JSON response into out.
func (c *Client) doPost(ctx context.Context, service, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("gcp: marshal request for %s: %w", service, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("gcp: build request for %s: %w", service, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("gcp: call %s: %w", service, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap so an oversized body is caught explicitly rather
	// than fed to json.Unmarshal as silently truncated (and thus garbled) JSON.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		// A failed read must not hide the status, which is the actionable half.
		if !isSuccess(resp.StatusCode) {
			return &APIError{Service: service, StatusCode: resp.StatusCode}
		}
		return fmt.Errorf("gcp: read response from %s: %w", service, err)
	}
	// Classify the status before the size check, so an oversized error page still
	// reports the status instead of only its size.
	if !isSuccess(resp.StatusCode) {
		return &APIError{
			Service:    service,
			StatusCode: resp.StatusCode,
			Body:       truncateForError(strings.TrimSpace(string(data))),
		}
	}
	if len(data) > maxBodyBytes {
		return fmt.Errorf("gcp: response from %s exceeded %d bytes", service, maxBodyBytes)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("gcp: decode %d-byte response from %s: %w", len(data), service, err)
	}
	return nil
}

func isSuccess(status int) bool { return status >= 200 && status < 300 }

// validHeaderFieldName reports whether s is usable as an HTTP header name: only
// letters, digits and !#$%&'*+-.^_`|~.
func validHeaderFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)):
		default:
			return false
		}
	}
	return true
}

// validHeaderFieldValue reports whether s is usable as an HTTP header value. It
// matches what net/http accepts on the wire — printable bytes, space and
// horizontal tab — so a CR or LF can never reach a request.
func validHeaderFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '\t' && (c < ' ' || c == 0x7f) {
			return false
		}
	}
	return true
}

// truncateForError caps service-controlled text so a large (e.g. HTML gateway)
// response doesn't bloat the returned error.
func truncateForError(s string) string {
	if len(s) <= maxErrorBytes {
		return s
	}
	cut := maxErrorBytes
	// Drop a rune that straddles the cap so it is not sliced into a mangled
	// partial. A body need not be UTF-8 at all: when the bytes before the cap do
	// not begin one rune, keep them rather than discard diagnostic context.
	if r, size := utf8.DecodeLastRuneInString(s[:cut]); r == utf8.RuneError && size <= 1 {
		for i := 1; i < utf8.UTFMax && cut-i > 0; i++ {
			if !utf8.RuneStart(s[cut-i]) {
				continue
			}
			if _, n := utf8.DecodeRuneInString(s[cut-i:]); cut-i+n > cut {
				cut -= i
			}
			break
		}
	}
	return s[:cut] + "..."
}
