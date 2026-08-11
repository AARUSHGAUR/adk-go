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

package compaction

import (
	"fmt"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
)

// NewSummaryEvent builds the event a [Summarizer] returns from the summary it
// produced. Implementations should call it rather than assembling the event
// themselves: it derives the range the summary covers, applies the authorship
// a stored summary needs, and refuses input that would produce a broken
// compaction.
//
// The returned event carries no ID, invocation ID or timestamp. The framework
// assigns those when it appends the event, and deliberately gives the summary
// a fresh invocation ID rather than one belonging to a covered turn, because
// sliding-window selection counts invocations. That is why this takes no
// context.Context where [session.NewEvent] does.
//
// events must be non-empty and in chronological order, and summary must be
// non-nil and hold text. usage may be nil. An error is returned rather than a
// silently broken event, because a range that covers nothing leaves the
// compacted turns in every future prompt while still consuming a summary.
// [session.EventCompaction] is a plain struct with no constructor to validate
// in, so the checks live here, at the supported way to build one.
func NewSummaryEvent(events []*session.Event, summary *genai.Content, usage *genai.GenerateContentResponseUsageMetadata) (*session.Event, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("cannot summarize an empty event list")
	}
	// An empty summary is rejected, not just a nil one. Recording a compaction
	// whose content says nothing deletes the covered turns from every future
	// prompt and puts nothing in their place, which is worse than not
	// compacting at all.
	if !hasText(summary) {
		return nil, fmt.Errorf("summary content is empty, so compacting would delete the covered events and replace them with nothing")
	}
	start, end := events[0].Timestamp, events[len(events)-1].Timestamp
	if end.Before(start) {
		return nil, fmt.Errorf("events are not in chronological order: first event is at %v, last at %v", start, end)
	}

	content := *summary
	content.Role = "model"
	return &session.Event{
		// Authored as "user" because a summary is injected context rather than
		// something the agent said. It is re-authored as "model" when
		// materialized into a prompt, so the model reads it as prior context.
		Author: "user",
		Actions: session.EventActions{
			Compaction: &session.EventCompaction{
				StartTimestamp:   start,
				EndTimestamp:     end,
				CompactedContent: &content,
			},
		},
		LLMResponse: model.LLMResponse{UsageMetadata: usage},
	}, nil
}
