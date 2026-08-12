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
	"fmt"
	"unicode/utf8"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/internal/telemetry"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/session/compaction"
)

// TokenCounter estimates the prompt token count implied by events.
//
// It is consulted only when no event carries an observed prompt token count,
// for instance before the first model response of a session. Returning zero
// means the count could not be determined, which suppresses compaction.
type TokenCounter func(events []*session.Event) int

// ProgressGate decides whether another compaction at a given prompt size is
// worth attempting, and remembers the ones that happen.
//
// It exists so the caller can stop compaction repeating uselessly within one
// turn without this package needing to know what an invocation is.
type ProgressGate interface {
	AllowAt(tokens int) bool
	RecordAt(tokens int)
	Recovered()
}

// TailRetention summarizes everything but the most recent events once the
// prompt has grown past cfg.TokenThreshold, and returns the resulting
// compaction event, ready for the caller to append to the session.
//
// It returns a nil event, and no error, whenever there is nothing to do: the
// threshold is not reached, too few events exist beyond the retained tail, the
// window has no self-contained prefix, or the summarizer declined.
//
// Unlike [SlidingWindow] this runs *inside* an invocation, before a model call,
// which is what lets it react to a single long turn rather than waiting for the
// turn to end. Callers must run it before assembling contents so the fresh
// summary is reflected in the request.
func TailRetention(ctx context.Context, cfg *compaction.Config, sess session.Session, estimate TokenCounter, progress ProgressGate) (*session.Event, error) {
	if !HasTailRetention(cfg) {
		return nil, nil
	}
	if cfg.Summarizer == nil {
		return nil, fmt.Errorf("no Summarizer configured")
	}
	if sess == nil {
		return nil, nil
	}

	events := collect(sess)
	tokens, ok := promptTokenCount(events, estimate)
	if !ok {
		return nil, nil
	}
	if tokens < cfg.TokenThreshold {
		// Under the threshold, so any earlier compaction in this turn did its
		// job. Re-arm, or a turn that grows again could never compact again.
		if progress != nil {
			progress.Recovered()
		}
		return nil, nil
	}

	// Stop here when the last compaction in this turn has not yet brought the
	// prompt back under the threshold. Compacting again would summarize a
	// little more and leave the prompt just as far over it, paying for a model
	// call each time.
	if progress != nil && !progress.AllowAt(tokens) {
		traceDeclined(ctx, cfg, sess, telemetry.CompactionTriggerTokenThreshold, "the previous compaction did not bring the prompt back under the threshold")
		return nil, nil
	}

	window := selectTailRetentionWindow(events, cfg.EventRetentionSize)
	if len(window) == 0 {
		// The threshold is crossed and nothing can be summarized: the retained
		// tail is the whole history, or the window has no self-contained prefix
		// because a tool call at its head is still unanswered. Silence here is
		// indistinguishable from an idle session, while the prompt keeps growing
		// on every turn, so it is recorded.
		traceDeclined(ctx, cfg, sess, telemetry.CompactionTriggerTokenThreshold, "no compactable window past the retained tail")
		return nil, nil
	}

	summary, err := summarizeTraced(ctx, cfg, sess, telemetry.CompactionTriggerTokenThreshold, window)
	if err != nil {
		return nil, fmt.Errorf("tail-retention summarization failed: %w", err)
	}
	// Recorded only now. A failed attempt must leave the gate as it found it,
	// or one transient summarizer error disarms compaction for the rest of the
	// invocation and the prompt grows unchecked behind it.
	if progress != nil && summary != nil {
		progress.RecordAt(tokens)
	}
	return summary, nil
}

// charsPerToken is the crude characters-to-tokens ratio used when no model has
// reported a real prompt token count yet.
const charsPerToken = 4

// promptTokenCount returns the most recently observed prompt token count in
// events, falling back to estimate when no event reports one.
//
// The observed count is preferred because it is what the model actually
// charged for the last call, which accounts for the system instruction, tool
// declarations and non-text parts that a character count cannot see. The
// estimate only matters before the first model response of a session.
//
// The second result is false when no count could be determined, which callers
// treat as "do not compact yet".
func promptTokenCount(events []*session.Event, estimate TokenCounter) (int, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		// Skip compaction events. A summary carries the usage metadata of the
		// summarizer's own call, which measures the transcript it was handed
		// rather than the agent's prompt. Reading it latches compaction on: the
		// summarizer's count is typically far above the threshold, so every
		// later turn sees the threshold crossed and compacts again.
		if hasCompaction(events[i]) {
			continue
		}
		if usage := events[i].UsageMetadata; usage != nil && usage.PromptTokenCount > 0 {
			// Add an estimate for everything appended since that count was
			// reported. The reported number describes the prompt of an earlier
			// call, so on its own it lags by however much the turn has grown:
			// in a tool loop that is every call and response since, which is
			// exactly the growth compaction exists to catch. The call that
			// first crosses the threshold would otherwise be invisible until
			// the next one.
			tokens := int(usage.PromptTokenCount)
			if estimate != nil && i < len(events)-1 {
				tokens += estimate(events[i+1:])
			}
			return tokens, true
		}
	}
	if estimate == nil {
		return 0, false
	}
	if tokens := estimate(events); tokens > 0 {
		return tokens, true
	}
	return 0, false
}

// EstimateTokensFromContents returns a crude token estimate for contents, by
// counting text characters and dividing by [charsPerToken].
//
// It exists so callers that already build prompt contents can reuse the same
// approximation the other ADK implementations use, rather than inventing their
// own.
//
// It counts only text parts, so it under-counts a prompt dominated by inline
// data, and it sees nothing outside contents -- notably not the system
// instruction or tool declarations, which for an agent with many tools or a
// large skills catalogue can dominate. It is therefore a floor, not an
// estimate, and is consulted only until the first model response reports a real
// prompt token count.
func EstimateTokensFromContents(contents []*genai.Content) int {
	textChars := 0
	for _, content := range contents {
		if content == nil {
			continue
		}
		for _, part := range content.Parts {
			if part != nil {
				textChars += utf8.RuneCountInString(part.Text)
			}
		}
	}
	if textChars <= 0 {
		return 0
	}
	return textChars / charsPerToken
}

// selectTailRetentionWindow returns the events a tail-retention compaction
// should summarize, or nil when there is nothing to compact.
//
// It takes every event since the last compaction except the most recent
// retentionSize, which stay raw so the model keeps immediate continuity, and
// trims the result with longestSelfContainedPrefix.
//
// When an earlier compaction exists its summary is prepended to the window, so
// the new summary covers and supersedes it. That keeps history as one rolling
// summary plus a raw tail, rather than an ever-growing chain of summaries.
func selectTailRetentionWindow(events []*session.Event, retentionSize int) []*session.Event {
	if retentionSize < 0 {
		return nil
	}

	latest := LatestCompactionEvent(events)

	// Candidates are the events recorded after the previous compaction, by
	// stream position rather than by timestamp.
	//
	// Timestamps got this wrong at the boundary. The filter excluded anything
	// not strictly after the previous end, while the new range, seeded with the
	// previous summary, starts back at the previous start and so covers that
	// instant. An event stamped exactly at the old end but appended after the
	// old compaction therefore fell in no window at all and inside the next
	// recorded range: summarized by nothing, and dropped from every later
	// prompt. Position has no ties.
	start := 0
	if latest != nil {
		for i, ev := range events {
			if ev == latest {
				start = i + 1
				break
			}
		}
	}
	var candidates []*session.Event
	for _, ev := range events[start:] {
		if hasCompaction(ev) {
			continue
		}
		candidates = append(candidates, ev)
	}
	if len(candidates) <= retentionSize {
		return nil
	}

	// firstRetained is where the raw tail begins; everything before it is
	// eligible for summarization.
	firstRetained := len(candidates)
	if retentionSize > 0 {
		firstRetained -= retentionSize
		// Move the cut back past any same-timestamp group. Compaction coverage
		// is inclusive of EndTimestamp, so a retained event sharing a timestamp
		// with the last summarized one would be dropped from the prompt despite
		// never having been summarized.
		boundary := candidates[firstRetained].Timestamp
		for firstRetained > 0 && !candidates[firstRetained-1].Timestamp.Before(boundary) {
			firstRetained--
		}
	}

	// A summary inherits the branch and isolation scope of what it covers, so
	// the window has to be homogeneous in both. A slice of a multi-agent
	// session routinely spans branches, and summarizing across one folds a
	// sub-agent's content into a summary the parent can read, defeating the
	// filters that keep those apart.
	window := longestSelfContainedPrefix(trimToOneScope(candidates[:firstRetained]))
	if len(window) == 0 {
		return nil
	}

	if latest == nil {
		return window
	}

	// Seed the window with the previous summary, timestamped at the start of
	// the range it covered. The new compaction therefore spans a strictly wider
	// range, which subsumes the old one at prompt-build time.
	//
	// The seed carries the previous summary's branch and isolation scope. It
	// stands in for events that had them, and leaving the scope empty would
	// make every summary built on top of it universally visible.
	prev := latest.Actions.Compaction
	seed := &session.Event{
		// Labelled as the previous summary rather than left anonymous. Without
		// it the seed is indistinguishable from an ordinary model turn, so the
		// transcript renders a summary as if the agent had said it, and nothing
		// downstream can tell how many times content has been re-summarized.
		// The previous summary's own identity, so the compaction built on top
		// of it inherits everything it stood for and supersedes it cleanly.
		// A synthetic ID here would leave the old record covering events the
		// new one does not, and both would materialize into the same prompt.
		ID:             latest.ID,
		Author:         "model",
		Timestamp:      prev.StartTimestamp,
		Branch:         latest.Branch,
		IsolationScope: latest.IsolationScope,
		LLMResponse:    model.LLMResponse{Content: prev.CompactedContent},
		Actions:        session.EventActions{Compaction: prev},
	}
	if seed.Branch != window[0].Branch || seed.IsolationScope != window[0].IsolationScope {
		// The rolling summary belongs to a different scope than the window that
		// would extend it. Compact the window on its own rather than merging
		// across the boundary.
		return window
	}
	return append([]*session.Event{seed}, window...)
}
