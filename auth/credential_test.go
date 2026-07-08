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

package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"

	"google.golang.org/adk/v2/auth"
)

func TestCredentialApply(t *testing.T) {
	tests := []struct {
		name    string
		cred    *auth.Credential
		want    http.Header
		wantErr bool
	}{
		{
			name: "api key",
			cred: &auth.Credential{APIKey: &auth.APIKeyCredential{Name: "X-Api-Key", Value: "secret"}},
			want: http.Header{"X-Api-Key": {"secret"}},
		},
		{
			name: "bearer",
			cred: &auth.Credential{HTTP: &auth.HTTPCredential{Scheme: "bearer", Token: "abc"}},
			want: http.Header{"Authorization": {"Bearer abc"}},
		},
		{
			name: "empty scheme defaults to bearer",
			cred: &auth.Credential{HTTP: &auth.HTTPCredential{Token: "abc"}},
			want: http.Header{"Authorization": {"Bearer abc"}},
		},
		{
			name: "basic",
			cred: &auth.Credential{HTTP: &auth.HTTPCredential{Scheme: "basic", Username: "u", Password: "p"}},
			// base64("u:p") == "dTpw"
			want: http.Header{"Authorization": {"Basic dTpw"}},
		},
		{
			name: "bearer with additional headers",
			cred: &auth.Credential{HTTP: &auth.HTTPCredential{
				Scheme:            "bearer",
				Token:             "abc",
				AdditionalHeaders: map[string]string{"X-Extra": "1"},
			}},
			want: http.Header{"Authorization": {"Bearer abc"}, "X-Extra": {"1"}},
		},
		{
			name: "oauth2 static access token",
			cred: &auth.Credential{OAuth2: &auth.OAuth2Credential{AccessToken: "tok"}},
			want: http.Header{"Authorization": {"Bearer tok"}},
		},
		{
			name: "oauth2 token source",
			cred: &auth.Credential{OAuth2: &auth.OAuth2Credential{
				TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fresh", TokenType: "Bearer"}),
			}},
			want: http.Header{"Authorization": {"Bearer fresh"}},
		},
		{
			name:    "nil credential",
			cred:    nil,
			wantErr: true,
		},
		{
			name:    "empty credential",
			cred:    &auth.Credential{},
			wantErr: true,
		},
		{
			name: "multiple kinds set",
			cred: &auth.Credential{
				APIKey: &auth.APIKeyCredential{Name: "X", Value: "y"},
				HTTP:   &auth.HTTPCredential{Token: "z"},
			},
			wantErr: true,
		},
		{
			name:    "api key missing name",
			cred:    &auth.Credential{APIKey: &auth.APIKeyCredential{Value: "y"}},
			wantErr: true,
		},
		{
			name:    "bearer missing token",
			cred:    &auth.Credential{HTTP: &auth.HTTPCredential{Scheme: "bearer"}},
			wantErr: true,
		},
		{
			name:    "unsupported http scheme",
			cred:    &auth.Credential{HTTP: &auth.HTTPCredential{Scheme: "digest", Token: "x"}},
			wantErr: true,
		},
		{
			name:    "oauth2 consent pending",
			cred:    &auth.Credential{OAuth2: &auth.OAuth2Credential{AuthURI: "https://consent"}},
			wantErr: true,
		},
		{
			name:    "oauth2 missing token",
			cred:    &auth.Credential{OAuth2: &auth.OAuth2Credential{}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			err := tt.cred.Apply(h)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Apply() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Apply() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tt.want, h); diff != "" {
				t.Errorf("header mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOAuth2TokenSourceError(t *testing.T) {
	cred := &auth.Credential{OAuth2: &auth.OAuth2Credential{TokenSource: errTokenSource{}}}
	if err := cred.Apply(http.Header{}); err == nil {
		t.Fatal("Apply() = nil error, want error from failing token source")
	}
}

type errTokenSource struct{}

func (errTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("token source failure")
}
