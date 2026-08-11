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

package compactionctx

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/session/compaction"
)

func TestFromContextWithoutRuntime(t *testing.T) {
	t.Parallel()

	rt := FromContext(context.Background())
	if rt != nil {
		t.Errorf("FromContext() = %v on a bare context, want nil", rt)
	}
	// The nil receiver must answer, not panic: every caller reaches these
	// through a context that may not carry a runtime.
	if rt.Configured() || rt.Enabled() || rt.AlreadyCompacted() {
		t.Error("a nil runtime reported itself as usable")
	}
	rt.MarkCompacted() // must not panic
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	want := &Runtime{Config: &compaction.Config{CompactionInterval: 2}, SessionService: session.InMemoryService()}
	got := FromContext(ToContext(context.Background(), want))
	if got != want {
		t.Fatalf("FromContext() returned %v, want the runtime that was stored", got)
	}
	if !got.Configured() {
		t.Error("Configured() = false for a runtime with a config")
	}
}

// TestMarkCompactedIsSafeUnderConcurrency covers the reason this is an atomic
// rather than a plain bool: sub-agents in a parallel workflow share one runtime.
func TestMarkCompactedIsSafeUnderConcurrency(t *testing.T) {
	t.Parallel()

	rt := &Runtime{Config: &compaction.Config{CompactionInterval: 1}}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rt.MarkCompacted()
			_ = rt.AlreadyCompacted()
		}()
	}
	wg.Wait()
	if !rt.AlreadyCompacted() {
		t.Error("AlreadyCompacted() = false after MarkCompacted()")
	}
}
