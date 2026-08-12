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
func newSummaryEvent(events []*session.Event, summary *genai.Content, usage *genai.GenerateContentResponseUsageMetadata) (*session.Event, error) {
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

	// The events this summary stands in for, named rather than described by
	// their span. Everything the window filtered out keeps its place in the
	// prompt, whatever its timestamp says.
	//
	// An event with no ID is left out. It cannot be named, so it cannot be
	// covered, and leaving it raw beside a summary of it is the recoverable
	// half of that choice. AppendEvent assigns an ID to anything that arrives
	// without one, so a stored event reaching here should always have one.
	covered := make([]string, 0, len(events))
	for _, ev := range events {
		if ev.ID != "" {
			covered = append(covered, ev.ID)
		}
		// A summary in the window is a rolling seed: this compaction restates
		// it, so it stands in for what that one stood in for as well.
		// Otherwise the older record would keep covering events this one does
		// not, and both would be materialized into the same prompt.
		if c := ev.Actions.Compaction; c != nil {
			covered = append(covered, c.CoveredEventIDs...)
		}
	}
	slices.Sort(covered)
	covered = slices.Compact(covered)

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
				CoveredEventIDs:  covered,
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
