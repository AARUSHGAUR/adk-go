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
	"fmt"
	"slices"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/internal/utils"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
)

// newSummaryEvent builds the event that carries a summary: it names the events
// the summary replaces, derives the bounding box over them, and applies the
// authorship a stored summary needs.
//
// The returned event carries no ID, invocation ID or timestamp. Those are
// assigned when it is appended, and the invocation ID is deliberately fresh
// rather than one belonging to a covered turn, because sliding-window selection
// counts invocations.
//
// Only prose parts of summary survive into the stored event. Whatever a
// summarizer returns is replayed into later prompts as though the framework had
// produced it, so a function call it invented or was tricked into emitting
// cannot ride along, and a thought is not something the model chose to say.
//
// events must be non-empty and hold no nil element, and summary must be
// non-nil and hold prose. usage may be nil. Bad input is an error rather than
// a silently broken event, because a compaction that stands for nothing still
// costs a model call and still leaves the prompt as large as it was.
func newSummaryEvent(events, all []*session.Event, summary *genai.Content, usage *genai.GenerateContentResponseUsageMetadata) (*session.Event, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("cannot summarize an empty event list")
	}
	// An empty summary is rejected, not just a nil one. Recording a compaction
	// whose content says nothing deletes the covered turns from every future
	// prompt and puts nothing in their place, which is worse than not
	// compacting at all.
	if !hasProse(summary) {
		return nil, fmt.Errorf("summary content is empty, so compacting would delete the covered events and replace them with nothing")
	}
	// NewSummaryEvent is exported and called by third-party Summarizer
	// implementations, so a nil element is an input to reject rather than a
	// panic to hand back.
	for i, ev := range events {
		if ev == nil {
			return nil, fmt.Errorf("events[%d] is nil", i)
		}
	}
	// The bounding box over the window, taken as a true minimum and maximum
	// rather than as its first and last element.
	//
	// A stored event list is in append order, and a timestamp is stamped when
	// an event is created, so two invocations in flight on one session leave
	// the list non-monotonic with a single clock and no skew. Requiring the
	// window to be sorted rejected exactly those sessions, and because nothing
	// was then recorded the same window was re-selected and re-rejected on
	// every later turn: two overlapping invocations were enough to stop a
	// session compacting for good.
	//
	// Widening the box to the true span is safe now that the covered set names
	// its events. It could not be done while coverage was the interval itself,
	// because stretching the interval past the window's own endpoints would
	// swallow events that were never summarized.
	start, end := events[0].Timestamp, events[0].Timestamp
	for _, ev := range events[1:] {
		if ev.Timestamp.Before(start) {
			start = ev.Timestamp
		}
		if ev.Timestamp.After(end) {
			end = ev.Timestamp
		}
	}

	// Only prose survives into the stored summary. Whatever the summarizer
	// returns is injected into later prompts verbatim, so a non-text part
	// reaches the model as if the framework had produced it. A hallucinated or
	// maliciously supplied FunctionCall would arrive unpaired, and a model may
	// act on it. A summary is prose by definition, so anything else is dropped.
	//
	// A surviving part is copied whole rather than rebuilt from its text. A
	// text part can carry metadata that belongs with it and that the model
	// expects back, a thought signature above all, and rebuilding would drop
	// that silently.
	content := genai.Content{Role: "model"}
	for _, p := range summary.Parts {
		if !utils.IsProsePart(p) {
			continue
		}
		part := *p
		content.Parts = append(content.Parts, &part)
	}
	if len(content.Parts) == 0 {
		return nil, fmt.Errorf("summary content holds no prose, so compacting would delete the covered events and replace them with nothing")
	}

	// The summary inherits the branch and isolation scope of what it covers.
	// Without them it carries Branch "" and IsolationScope "", which every
	// branch filter admits and which makes it visible outside the scope its
	// source events belonged to, leaking scoped content across the boundary the
	// filters exist to enforce.
	branch, scope := events[0].Branch, events[0].IsolationScope

	// The holes: events inside the range that this summary does not stand in
	// for, because window selection filtered them out. Everything else in the
	// range is covered, so the common case, a window with no holes in it,
	// records nothing here at all.
	//
	// An event with no ID cannot be named, so it cannot be excluded either. It
	// therefore reads as covered, which is the same answer the range alone gave
	// before any of this existed. AppendEvent assigns an ID to anything that
	// arrives without one, so a stored event reaching here should always have
	// one to name.
	summarized := make(map[string]struct{}, len(events))
	for _, ev := range events {
		if ev.ID != "" {
			summarized[ev.ID] = struct{}{}
		}
	}
	var excluded []string
	for _, ev := range all {
		if ev == nil || ev.ID == "" || hasCompaction(ev) {
			continue
		}
		if ev.Timestamp.Before(start) || ev.Timestamp.After(end) {
			continue
		}
		if _, ok := summarized[ev.ID]; ok {
			continue
		}
		excluded = append(excluded, ev.ID)
	}
	slices.Sort(excluded)
	excluded = slices.Compact(excluded)

	return &session.Event{
		// Authored as "user" because a summary is injected context rather than
		// something the agent said. It is re-authored as "model" when
		// materialized into a prompt, so the model reads it as prior context.
		Author:         "user",
		Branch:         branch,
		IsolationScope: scope,
		Actions: session.EventActions{
			Compaction: &session.EventCompaction{
				StartTimestamp:   start,
				EndTimestamp:     end,
				CompactedContent: &content,
				ExcludedEventIDs: excluded,
			},
		},
		LLMResponse: model.LLMResponse{UsageMetadata: usage},
	}, nil
}

// hasProse reports whether c carries at least one prose part.
func hasProse(c *genai.Content) bool {
	if c == nil {
		return false
	}
	for _, p := range c.Parts {
		if utils.IsProsePart(p) {
			return true
		}
	}
	return false
}

// SanitizeSummary strips anything from a compaction record that must not reach
// a prompt, and reports whether the record is still usable.
//
// The framework builds a summary event and filters its content, but a plugin
// can replace that event wholesale on its way to the session, and the
// replacement went to storage unexamined. A plugin returning content with a
// text part and a FunctionCall got that unpaired call into a real model prompt,
// which is the exact thing the filter on the summarizer path exists to stop.
//
// Reports false when nothing usable survives, which the caller treats as a
// summary not worth storing rather than as an error: the plugin was within its
// rights to redact everything.
func SanitizeSummary(ev *session.Event) bool {
	if ev == nil || ev.Actions.Compaction == nil {
		return false
	}
	c := ev.Actions.Compaction.CompactedContent
	if c == nil {
		return false
	}
	kept := make([]*genai.Part, 0, len(c.Parts))
	for _, p := range c.Parts {
		if utils.IsProsePart(p) {
			part := *p
			kept = append(kept, &part)
		}
	}
	if len(kept) == 0 {
		return false
	}
	content := *c
	content.Parts = kept
	ev.Actions.Compaction.CompactedContent = &content
	return true
}
