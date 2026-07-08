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
	"context"
	"errors"
	"testing"

	"golang.org/x/oauth2"
)

func TestLazyTokenSourceMemoizesSuccess(t *testing.T) {
	calls := 0
	p := lazyTokenSource(func(context.Context) (oauth2.TokenSource, error) {
		calls++
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}), nil
	})

	for i := range 3 {
		cred, err := p.Credential(t.Context())
		if err != nil {
			t.Fatalf("call %d: Credential() error = %v", i, err)
		}
		if cred.OAuth2 == nil || cred.OAuth2.TokenSource == nil {
			t.Fatalf("call %d: missing token source", i)
		}
	}
	if calls != 1 {
		t.Errorf("init called %d times, want 1 (success should be memoized)", calls)
	}
}

func TestLazyTokenSourceRetriesFailure(t *testing.T) {
	calls := 0
	boom := errors.New("boom")
	p := lazyTokenSource(func(context.Context) (oauth2.TokenSource, error) {
		calls++
		if calls == 1 {
			return nil, boom
		}
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"}), nil
	})

	if _, err := p.Credential(t.Context()); !errors.Is(err, boom) {
		t.Fatalf("first call error = %v, want %v", err, boom)
	}
	if _, err := p.Credential(t.Context()); err != nil {
		t.Fatalf("second call error = %v, want nil (failure must not be memoized)", err)
	}
	if calls != 2 {
		t.Errorf("init called %d times, want 2", calls)
	}
}
