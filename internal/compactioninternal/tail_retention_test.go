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

package compactioninternal

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/genai"

	"google.golang.org/adk/v2/internal/utils"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/session/compaction"
)

// withUsage tags an event with an observed prompt token count.
func withUsage(ev *session.Event, promptTokens int32) *session.Event {
	ev.LLMResponse.UsageMetadata = &genai.GenerateContentResponseUsageMetadata{
		PromptTokenCount: promptTokens,
	}
	return ev
}

func TestSelectTailRetentionWindow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		events    []*session.Event
		retention int
		want      []string
	}{
		{
			name:      "fewer events than the retention size",
			events:    []*session.Event{textEvent("a", "inv1", 1, "q1"), textEvent("b", "inv1", 2, "a1")},
			retention: 5,
			want:      nil,
		},
		{
			name:      "exactly the retention size keeps everything raw",
			events:    []*session.Event{textEvent("a", "inv1", 1, "q1"), textEvent("b", "inv1", 2, "a1")},
			retention: 2,
			want:      nil,
		},
		{
			name: "older events are compacted, the tail stays raw",
			events: []*session.Event{
				textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
				textEvent("c", "inv2", 3, "q2"), modelTextEvent("d", "inv2", 4, "a2"),
			},
			retention: 2,
			want:      []string{"a", "b"},
		},
		{
			name: "zero retention compacts everything",
			events: []*session.Event{
				textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
			},
			retention: 0,
			want:      []string{"a", "b"},
		},
		{
			name: "the cut moves back past a same-timestamp group",
			events: []*session.Event{
				textEvent("a", "inv1", 1, "q1"),
				// b, c and d all share timestamp 2. Cutting between them would
				// give the summary an EndTimestamp that also covers a retained
				// event, silently dropping it from the prompt.
				modelTextEvent("b", "inv1", 2, "a1"),
				modelTextEvent("c", "inv1", 2, "a2"),
				modelTextEvent("d", "inv1", 2, "a3"),
			},
			retention: 2,
			want:      []string{"a"},
		},
		{
			name: "a whole same-timestamp tail leaves nothing to compact",
			events: []*session.Event{
				modelTextEvent("a", "inv1", 2, "a1"),
				modelTextEvent("b", "inv1", 2, "a2"),
				modelTextEvent("c", "inv1", 2, "a3"),
			},
			retention: 1,
			want:      nil,
		},
		{
			name: "window is trimmed so a call is not split from its response",
			events: []*session.Event{
				textEvent("a", "inv1", 1, "q1"),
				callEvent("b", "inv1", 2, "c1"),
				responseEvent("c", "inv1", 3, "c1"),
				modelTextEvent("d", "inv1", 4, "a1"),
			},
			// Cutting at 3 would compact [a, b] and strand the response.
			retention: 1,
			want:      []string{"a", "b", "c"},
		},
		{
			name: "nil when the compactable prefix is entirely an open call",
			events: []*session.Event{
				callEvent("a", "inv1", 1, "c1"),
				responseEvent("b", "inv1", 2, "c1"),
				modelTextEvent("c", "inv1", 3, "a1"),
			},
			retention: 2,
			want:      nil,
		},
		{
			name: "only events after the previous compaction are candidates",
			events: []*session.Event{
				textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
				compactionEvent("s1", 3, 1, 2, "earlier summary"),
				textEvent("c", "inv2", 4, "q2"), modelTextEvent("d", "inv2", 5, "a2"),
				textEvent("e", "inv3", 6, "q3"), modelTextEvent("f", "inv3", 7, "a3"),
			},
			retention: 2,
			// The prior summary is seeded in under its own ID, so the new
			// compaction inherits what it covered and supersedes it.
			want: []string{"s1", "c", "d"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ids(selectTailRetentionWindow(tc.events, tc.retention, ""))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("selectTailRetentionWindow(retention=%d) mismatch (-want +got):\n%s", tc.retention, diff)
			}
		})
	}
}

// TestSelectTailRetentionWindowSeedsPreviousSummary checks the rolling-summary
// seed: the new window opens with the previous summary, timestamped at the
// start of the range that summary covered, so the new compaction subsumes it.
func TestSelectTailRetentionWindowSeedsPreviousSummary(t *testing.T) {
	t.Parallel()

	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
		compactionEvent("s1", 3, 1, 2, "earlier summary", "a", "b"),
		textEvent("c", "inv2", 4, "q2"), modelTextEvent("d", "inv2", 5, "a2"),
		textEvent("e", "inv3", 6, "q3"), modelTextEvent("f", "inv3", 7, "a3"),
	}

	window := selectTailRetentionWindow(events, 2, "")
	if len(window) == 0 {
		t.Fatal("selectTailRetentionWindow() returned nothing")
	}

	seed := window[0]
	if !seed.Timestamp.Equal(at(1)) {
		t.Errorf("seed timestamp = %v, want the previous compaction's start %v", seed.Timestamp, at(1))
	}
	if seed.Author != "model" {
		t.Errorf("seed author = %q, want %q", seed.Author, "model")
	}
	if got := utils.TextParts(utils.Content(seed)); len(got) != 1 || got[0] != "earlier summary" {
		t.Errorf("seed text = %v, want the previous summary", got)
	}

	// Summarizing this window must produce a range that strictly contains the
	// old one, so Apply treats the old summary as subsumed.
	summary, err := newSummaryEvent(window, genai.NewContentFromText("new summary", "model"), nil)
	if err != nil {
		t.Fatalf("newSummaryEvent() error = %v", err)
	}
	summary.ID, summary.Timestamp = "s2", at(8)
	if !summary.Actions.Compaction.StartTimestamp.Equal(at(1)) {
		t.Errorf("new summary starts at %v, want %v so it covers the old range",
			summary.Actions.Compaction.StartTimestamp, at(1))
	}

	got := ids(Apply(append(events, summary)))
	if diff := cmp.Diff([]string{"s2", "e", "f"}, got); diff != "" {
		t.Errorf("after the rolling compaction, prompt events mismatch (-want +got):\n%s", diff)
	}
}

func TestPromptTokenCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		events   []*session.Event
		estimate TokenCounter
		want     int
		wantOK   bool
	}{
		{
			name:   "no events and no estimator",
			want:   0,
			wantOK: false,
		},
		{
			name:     "estimator used when nothing reported a count",
			events:   []*session.Event{textEvent("a", "inv1", 1, "q1")},
			estimate: func([]*session.Event) int { return 123 },
			want:     123,
			wantOK:   true,
		},
		{
			name:     "estimator returning zero means unknown",
			events:   []*session.Event{textEvent("a", "inv1", 1, "q1")},
			estimate: func([]*session.Event) int { return 0 },
			want:     0,
			wantOK:   false,
		},
		{
			name: "observed count wins over the estimator",
			events: []*session.Event{
				withUsage(modelTextEvent("a", "inv1", 1, "a1"), 500),
			},
			estimate: func([]*session.Event) int { return 123 },
			want:     500,
			wantOK:   true,
		},
		{
			name: "the most recent observed count wins",
			events: []*session.Event{
				withUsage(modelTextEvent("a", "inv1", 1, "a1"), 500),
				textEvent("b", "inv2", 2, "q2"),
				withUsage(modelTextEvent("c", "inv2", 3, "a2"), 900),
			},
			want:   900,
			wantOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := promptTokenCount(tc.events, tc.estimate)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("promptTokenCount() = (%d, %t), want (%d, %t)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestEstimateTokensFromContents(t *testing.T) {
	t.Parallel()

	text := func(n int) *genai.Content {
		return &genai.Content{Parts: []*genai.Part{{Text: strings.Repeat("x", n)}}}
	}

	tests := []struct {
		name     string
		contents []*genai.Content
		want     int
	}{
		{name: "nil", contents: nil, want: 0},
		{name: "empty text", contents: []*genai.Content{text(0)}, want: 0},
		{name: "below one token", contents: []*genai.Content{text(3)}, want: 0},
		{name: "exactly one token", contents: []*genai.Content{text(4)}, want: 1},
		{name: "summed across contents", contents: []*genai.Content{text(2000), text(2000)}, want: 1000},
		{name: "nil content is skipped", contents: []*genai.Content{nil, text(4)}, want: 1},
		{name: "nil part is skipped", contents: []*genai.Content{{Parts: []*genai.Part{nil, {Text: "xxxx"}}}}, want: 1},
		{
			// Non-text parts are invisible to the estimate, which is why it is
			// only a floor until real usage metadata arrives.
			name:     "function call contributes nothing",
			contents: []*genai.Content{{Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{Name: "search"}}}}},
			want:     0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := EstimateTokensFromContents(tc.contents); got != tc.want {
				t.Errorf("EstimateTokensFromContents() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTailRetention(t *testing.T) {
	t.Parallel()

	fourEvents := []*session.Event{
		textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
		textEvent("c", "inv2", 3, "q2"), withUsage(modelTextEvent("d", "inv2", 4, "a2"), 900),
	}

	tests := []struct {
		name        string
		cfg         *compaction.Config
		events      []*session.Event
		summarizer  *fakeSummarizer
		wantSummary bool
		wantWindow  []string
		wantErr     bool
	}{
		{
			name:       "nil config does nothing",
			cfg:        nil,
			events:     fourEvents,
			summarizer: &fakeSummarizer{summary: "sum"},
		},
		{
			name:       "sliding-window-only config does nothing",
			cfg:        &compaction.Config{CompactionInterval: 2},
			events:     fourEvents,
			summarizer: &fakeSummarizer{summary: "sum"},
		},
		{
			name:       "below the threshold",
			cfg:        &compaction.Config{TokenThreshold: 1000, EventRetentionSize: 2},
			events:     fourEvents,
			summarizer: &fakeSummarizer{summary: "sum"},
		},
		{
			name:        "at the threshold",
			cfg:         &compaction.Config{TokenThreshold: 900, EventRetentionSize: 2},
			events:      fourEvents,
			summarizer:  &fakeSummarizer{summary: "sum"},
			wantSummary: true,
			wantWindow:  []string{"a", "b"},
		},
		{
			name:        "above the threshold",
			cfg:         &compaction.Config{TokenThreshold: 100, EventRetentionSize: 2},
			events:      fourEvents,
			summarizer:  &fakeSummarizer{summary: "sum"},
			wantSummary: true,
			wantWindow:  []string{"a", "b"},
		},
		{
			name:       "threshold reached but the tail retains everything",
			cfg:        &compaction.Config{TokenThreshold: 100, EventRetentionSize: 10},
			events:     fourEvents,
			summarizer: &fakeSummarizer{summary: "sum"},
		},
		{
			name:        "summarizer declines",
			cfg:         &compaction.Config{TokenThreshold: 100, EventRetentionSize: 2},
			events:      fourEvents,
			summarizer:  &fakeSummarizer{},
			wantSummary: false,
			wantWindow:  []string{"a", "b"},
		},
		{
			name:       "summarizer fails",
			cfg:        &compaction.Config{TokenThreshold: 100, EventRetentionSize: 2},
			events:     fourEvents,
			summarizer: &fakeSummarizer{err: errors.New("boom")},
			wantWindow: []string{"a", "b"},
			wantErr:    true,
		},
		{
			name:       "no observed token count and no estimate",
			cfg:        &compaction.Config{TokenThreshold: 1, EventRetentionSize: 1},
			events:     []*session.Event{textEvent("a", "inv1", 1, "q1"), textEvent("b", "inv1", 2, "q2")},
			summarizer: &fakeSummarizer{summary: "sum"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := tc.cfg
			if cfg != nil {
				copied := *cfg
				copied.Summarizer = tc.summarizer
				cfg = &copied
			}

			got, err := TailRetention(context.Background(), cfg, &staticSession{events: tc.events}, "", nil, nil)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("TailRetention() error = %v, wantErr %t", err, tc.wantErr)
			}
			if gotSummary := got != nil; gotSummary != tc.wantSummary {
				t.Errorf("TailRetention() returned event = %t, want %t", gotSummary, tc.wantSummary)
			}
			var gotWindow []string
			if len(tc.summarizer.windows) > 0 {
				gotWindow = tc.summarizer.windows[0]
			}
			if diff := cmp.Diff(tc.wantWindow, gotWindow); diff != "" {
				t.Errorf("summarizer window mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTailRetentionUsesTheEstimator(t *testing.T) {
	t.Parallel()

	// No event carries usage metadata, so the estimator decides.
	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
		textEvent("c", "inv2", 3, "q2"), modelTextEvent("d", "inv2", 4, "a2"),
	}
	summarizer := &fakeSummarizer{summary: "sum"}
	cfg := &compaction.Config{TokenThreshold: 500, EventRetentionSize: 2, Summarizer: summarizer}

	got, err := TailRetention(context.Background(), cfg, &staticSession{events: events}, "",
		func([]*session.Event) int { return 100 }, nil)
	if err != nil {
		t.Fatalf("TailRetention() error = %v", err)
	}
	if got != nil {
		t.Error("TailRetention() compacted despite an estimate below the threshold")
	}

	got, err = TailRetention(context.Background(), cfg, &staticSession{events: events}, "",
		func([]*session.Event) int { return 700 }, nil)
	if err != nil {
		t.Fatalf("TailRetention() error = %v", err)
	}
	if got == nil {
		t.Error("TailRetention() did not compact despite an estimate above the threshold")
	}
}

func TestTailRetentionRequiresSummarizer(t *testing.T) {
	t.Parallel()

	_, err := TailRetention(context.Background(), &compaction.Config{TokenThreshold: 1, EventRetentionSize: 0},
		&staticSession{events: []*session.Event{withUsage(modelTextEvent("a", "inv1", 1, "a"), 10)}}, "", nil, nil)
	if err == nil {
		t.Fatal("TailRetention() with no Summarizer returned nil error, want an error")
	}
}

func TestTailRetentionStampsTheSummary(t *testing.T) {
	t.Parallel()

	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"),
		withUsage(modelTextEvent("b", "inv1", 2, "a1"), 900),
	}
	cfg := &compaction.Config{TokenThreshold: 100, EventRetentionSize: 0, Summarizer: &fakeSummarizer{summary: "sum"}}

	got, err := TailRetention(context.Background(), cfg, &staticSession{events: events}, "", nil, nil)
	if err != nil {
		t.Fatalf("TailRetention() error = %v", err)
	}
	if got == nil {
		t.Fatal("TailRetention() produced no summary")
	}
	// The event must be ready to append without the caller filling anything in.
	if got.ID == "" {
		t.Error("summary has no ID")
	}
	if got.InvocationID == "" {
		t.Error("summary has no InvocationID")
	}
	if got.Timestamp.IsZero() {
		t.Error("summary has no Timestamp")
	}
	for _, ev := range events {
		if got.InvocationID == ev.InvocationID {
			t.Errorf("summary reuses invocation ID %q from a covered event; window selection counts invocations, so it must be fresh", got.InvocationID)
		}
	}
}

// TestTailRetentionThenApplyShrinksHistory is the round trip: compact, then
// build the prompt, and confirm the covered events are gone.
func TestTailRetentionThenApplyShrinksHistory(t *testing.T) {
	t.Parallel()

	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
		textEvent("c", "inv1", 3, "q2"), withUsage(modelTextEvent("d", "inv1", 4, "a2"), 5000),
	}
	cfg := &compaction.Config{TokenThreshold: 1000, EventRetentionSize: 2, Summarizer: &fakeSummarizer{summary: "SUMMARY"}}

	summary, err := TailRetention(context.Background(), cfg, &staticSession{events: events}, "", nil, nil)
	if err != nil {
		t.Fatalf("TailRetention() error = %v", err)
	}
	if summary == nil {
		t.Fatal("TailRetention() produced no summary")
	}
	summary.ID = "s1"

	got := Apply(append(events, summary))
	if diff := cmp.Diff([]string{"s1", "c", "d"}, ids(got)); diff != "" {
		t.Errorf("post-compaction prompt events mismatch (-want +got):\n%s", diff)
	}
	if texts := utils.TextParts(utils.Content(got[0])); len(texts) != 1 || texts[0] != "SUMMARY" {
		t.Errorf("first prompt event = %v, want the summary text", texts)
	}
}

// TestSelectTailRetentionWindowStaysInOneScope checks that the tail window stops
// at the first branch or isolation-scope change.
//
// A summary inherits the branch and isolation scope of what it covers, so a
// window spanning two of them produces one summary that necessarily misattributes
// half its content. Stamped with the first event's scope, it becomes readable by
// agents the filters exist to keep the rest away from.
func TestSelectTailRetentionWindowStaysInOneScope(t *testing.T) {
	t.Parallel()

	root1 := textEvent("a", "inv1", 1, "q1")
	root2 := modelTextEvent("b", "inv1", 2, "a1")
	sub := textEvent("c", "inv2", 3, "SUB-AGENT-SECRET")
	sub.Branch = "root.sub"
	sub.IsolationScope = "scope-1"
	tail1 := textEvent("d", "inv3", 4, "q3")
	tail2 := modelTextEvent("e", "inv3", 5, "a3")

	events := []*session.Event{root1, root2, sub, tail1, tail2}

	window := selectTailRetentionWindow(events, 2, "")
	if diff := cmp.Diff([]string{"a", "b"}, ids(window)); diff != "" {
		t.Errorf("selectTailRetentionWindow() mismatch (-want +got):\n%s\nthe window must stop at the scope change", diff)
	}
	for _, ev := range window {
		if ev.Branch != "" || ev.IsolationScope != "" {
			t.Errorf("event %q carries branch %q scope %q, so the window is not homogeneous", ev.ID, ev.Branch, ev.IsolationScope)
		}
	}
}

// TestSelectTailRetentionWindowKeepsATiedBoundaryEvent checks that an event
// stamped exactly at the previous compaction's end is not lost.
//
// The candidate filter used to exclude anything not strictly after that
// instant, while the new range, seeded with the previous summary, starts back
// at the previous start and so covers it. An event on that boundary therefore
// went into no window and inside the next recorded range: summarized by
// nothing, and dropped from every prompt afterwards.
func TestSelectTailRetentionWindowKeepsATiedBoundaryEvent(t *testing.T) {
	t.Parallel()

	prior := compactionEvent("s1", 3, 1, 3, "EARLIER")
	// Appended after the compaction, but stamped on its end instant.
	tied := textEvent("tied", "inv2", 3, "NEVER-SUMMARIZED")
	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"),
		modelTextEvent("b", "inv1", 2, "a1"),
		prior,
		tied,
		textEvent("c", "inv3", 4, "q3"),
		modelTextEvent("d", "inv3", 5, "a3"),
		textEvent("e", "inv4", 6, "q4"),
	}

	window := selectTailRetentionWindow(events, 1, "")
	if !slices.Contains(ids(window), "tied") {
		t.Errorf("window %v does not include the boundary event, so it is covered by the next range without being summarized", ids(window))
	}
}

// TestPromptTokenCountAddsEventsSinceTheLastReport checks that the count is not
// stale by a whole turn.
//
// A reported count describes the prompt of an earlier call. Returning it
// unchanged means everything appended since is invisible, so the call that
// first crosses the threshold is missed and compaction reacts one call late.
func TestPromptTokenCountAddsEventsSinceTheLastReport(t *testing.T) {
	t.Parallel()

	reported := modelTextEvent("a", "inv1", 1, "answer")
	reported.LLMResponse.UsageMetadata = &genai.GenerateContentResponseUsageMetadata{PromptTokenCount: 100}
	events := []*session.Event{
		reported,
		textEvent("b", "inv2", 2, strings.Repeat("x", 400)),
	}

	// The estimator stands in for the real one: four characters per token.
	estimate := func(evs []*session.Event) int {
		n := 0
		for _, ev := range evs {
			for _, p := range utils.Content(ev).Parts {
				n += len(p.Text)
			}
		}
		return n / 4
	}

	got, ok := promptTokenCount(events, estimate)
	if !ok {
		t.Fatal("promptTokenCount() reported nothing")
	}
	if got <= 100 {
		t.Errorf("promptTokenCount() = %d, want more than the reported 100: the 400 characters appended since are not counted", got)
	}
}

// recordingGate captures the [ProgressGate] calls TailRetention makes.
type recordingGate struct {
	allow     bool
	recorded  []int
	recovered int
}

func (g *recordingGate) AllowAt(int) bool { return g.allow }
func (g *recordingGate) RecordAt(t int)   { g.recorded = append(g.recorded, t) }
func (g *recordingGate) Recovered()       { g.recovered++ }

// TestTailRetentionReArmsTheGateBelowTheThreshold pins that a prompt back under
// the threshold re-arms the gate.
//
// Without this the gate closes on the first compaction of a turn and never
// reopens, so a long turn that keeps growing never compacts again.
func TestTailRetentionReArmsTheGateBelowTheThreshold(t *testing.T) {
	t.Parallel()

	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
		textEvent("c", "inv2", 3, "q2"), withUsage(modelTextEvent("d", "inv2", 4, "a2"), 100),
	}
	gate := &recordingGate{allow: true}
	cfg := &compaction.Config{TokenThreshold: 1000, EventRetentionSize: 2, Summarizer: &fakeSummarizer{summary: "sum"}}

	got, err := TailRetention(context.Background(), cfg, &staticSession{events: events}, "", nil, gate)
	if err != nil {
		t.Fatalf("TailRetention() error = %v", err)
	}
	if got != nil {
		t.Fatalf("TailRetention() returned a summary at 100 tokens against a 1000 threshold")
	}
	if gate.recovered != 1 {
		t.Errorf("Recovered() called %d times, want 1: a prompt under the threshold means the last compaction worked", gate.recovered)
	}
}

// TestTailRetentionDoesNotRecordAFailedAttempt pins that a summarizer failure
// leaves the progress gate as it found it.
//
// Recording the attempt rather than the result let one transient error disarm
// compaction for the whole invocation with nothing stored in exchange, and the
// prompt then grew unchecked behind a gate that had stopped retrying.
func TestTailRetentionDoesNotRecordAFailedAttempt(t *testing.T) {
	t.Parallel()

	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
		textEvent("c", "inv2", 3, "q2"), withUsage(modelTextEvent("d", "inv2", 4, "a2"), 900),
	}
	gate := &recordingGate{allow: true}
	cfg := &compaction.Config{TokenThreshold: 100, EventRetentionSize: 2, Summarizer: &fakeSummarizer{err: errors.New("boom")}}

	if _, err := TailRetention(context.Background(), cfg, &staticSession{events: events}, "", nil, gate); err == nil {
		t.Fatal("TailRetention() error = nil, want the summarizer failure")
	}
	if len(gate.recorded) != 0 {
		t.Errorf("RecordAt called %v after a failed summarization, want no calls", gate.recorded)
	}
}

// TestTailRetentionRecordsASuccessfulCompaction is the counterpart: a summary
// that was produced must close the gate.
func TestTailRetentionRecordsASuccessfulCompaction(t *testing.T) {
	t.Parallel()

	events := []*session.Event{
		textEvent("a", "inv1", 1, "q1"), modelTextEvent("b", "inv1", 2, "a1"),
		textEvent("c", "inv2", 3, "q2"), withUsage(modelTextEvent("d", "inv2", 4, "a2"), 900),
	}
	gate := &recordingGate{allow: true}
	cfg := &compaction.Config{TokenThreshold: 100, EventRetentionSize: 2, Summarizer: &fakeSummarizer{summary: "sum"}}

	got, err := TailRetention(context.Background(), cfg, &staticSession{events: events}, "", nil, gate)
	if err != nil || got == nil {
		t.Fatalf("TailRetention() = %v, %v, want a summary and no error", got, err)
	}
	if diff := cmp.Diff([]int{900}, gate.recorded); diff != "" {
		t.Errorf("RecordAt calls mismatch (-want +got):\n%s", diff)
	}
}

// TestSelectTailRetentionWindowKeepsTheLiveQuestion pins that the turn being
// answered keeps its own question.
//
// EventRetentionSize counts events and a turn is not a fixed number of them, so
// at every size Validate accepts the question can scroll out of the retained
// tail and be summarized into a paraphrase of the instruction being carried
// out. It is held back separately.
//
// The traffic after it stays eligible, which is the point: excluding the whole
// live invocation would stop a long tool loop compacting itself, and that is
// the case this strategy exists for.
func TestSelectTailRetentionWindowKeepsTheLiveQuestion(t *testing.T) {
	t.Parallel()

	events := []*session.Event{
		textEvent("q1", "inv1", 1, "older question"),
		modelTextEvent("a1", "inv1", 2, "older answer"),
		// The turn in flight: its question, then a long tool loop.
		textEvent("q2", "inv2", 3, "the question being answered"),
		modelTextEvent("t1", "inv2", 4, "tool step 1"),
		modelTextEvent("t2", "inv2", 5, "tool step 2"),
		modelTextEvent("t3", "inv2", 6, "tool step 3"),
	}

	got := ids(selectTailRetentionWindow(events, 2, "inv2"))

	if slices.Contains(got, "q2") {
		t.Error("the window covers the question the turn is answering")
	}
	// The loop's own older traffic is still compactable, skipping over the
	// question, which only a covered set can express.
	if diff := cmp.Diff([]string{"q1", "a1", "t1"}, got); diff != "" {
		t.Errorf("window mismatch (-want +got):\n%s", diff)
	}
}
