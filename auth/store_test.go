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
	"context"
	"testing"
	"time"

	"google.golang.org/adk/v2/auth"
)

func TestInMemoryCredentialStoreGetSet(t *testing.T) {
	ctx := context.Background()
	s := auth.NewInMemoryCredentialStore()
	key := auth.CredentialKey{AppName: "app", UserID: "user", Key: "res"}
	cred := &auth.Credential{HTTP: &auth.HTTPCredential{Scheme: "bearer", Token: "tok"}}

	if _, ok, err := s.Get(ctx, key); err != nil || ok {
		t.Fatalf("Get() on empty store = (_, %v, %v), want (_, false, nil)", ok, err)
	}
	if err := s.Set(ctx, key, cred, time.Time{}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, ok, err := s.Get(ctx, key)
	if err != nil || !ok || got != cred {
		t.Fatalf("Get() after Set = (%v, %v, %v), want the stored credential", got, ok, err)
	}

	// A different key is a miss.
	if _, ok, _ := s.Get(ctx, auth.CredentialKey{AppName: "app", UserID: "other", Key: "res"}); ok {
		t.Error("Get() for a different user = hit, want miss")
	}
}

func TestInMemoryCredentialStoreExpiry(t *testing.T) {
	ctx := context.Background()
	s := auth.NewInMemoryCredentialStore()
	key := auth.CredentialKey{Key: "res"}
	cred := &auth.Credential{APIKey: &auth.APIKeyCredential{Name: "X", Value: "v"}}

	if err := s.Set(ctx, key, cred, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, key); !ok {
		t.Error("Get() with far-future expiry = miss, want hit")
	}

	if err := s.Set(ctx, key, cred, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, key); ok {
		t.Error("Get() with past expiry = hit, want miss")
	}

	// Within the clock-skew window the entry is treated as expired.
	if err := s.Set(ctx, key, cred, time.Now().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, key); ok {
		t.Error("Get() within skew window = hit, want miss")
	}
}

func TestInMemoryCredentialStoreOverwrite(t *testing.T) {
	ctx := context.Background()
	s := auth.NewInMemoryCredentialStore()
	key := auth.CredentialKey{Key: "res"}
	first := &auth.Credential{HTTP: &auth.HTTPCredential{Token: "a"}}
	second := &auth.Credential{HTTP: &auth.HTTPCredential{Token: "b"}}

	if err := s.Set(ctx, key, first, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, key, second, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get(ctx, key); got != second {
		t.Fatalf("Get() after overwrite = %v, want the second credential", got)
	}
}
