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

// Package compactionctx carries the context-compaction runtime from the runner
// down to the request processors that need it.
//
// Those processors need the compaction config, and in one case the session
// service, and [agent.InvocationContext] exposes neither. Adding them to that
// interface would break every external implementation of it, so the runtime
// rides on the context.Context instead, the same way parentmap, runconfig and
// plugininternal already do.
package compactionctx

import (
	"context"
	"sync/atomic"

	"google.golang.org/adk/v2/internal/compactioninternal"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/session/compaction"
)

// Runtime is everything compaction needs that the invocation context does not
// already provide.
type Runtime struct {
	// config is the resolved compaction config, with its summarizer filled in.
	//
	// Unexported, with accessors, because one Runtime is shared by every
	// goroutine in an invocation. An exported pointer field invites a caller to
	// swap it mid-turn, and the config it points at is shared across every
	// invocation of the runner, so a mutation would leak between turns.
	config *compaction.Config
	// sessionService persists the summary events the compactor produces.
	sessionService session.Service

	// lastCompactionTokens is the prompt size that triggered the most recent
	// compaction in this invocation, or 0 if there has not been one.
	lastCompactionTokens atomic.Int64

	// compacted records that a compaction already ran in this invocation. A
	// Runtime is built per invocation, so it is the right scope for this, and
	// it is atomic because sub-agents running in parallel share one.
	compacted atomic.Bool
}

// New builds a Runtime. A nil config yields a nil Runtime, which every method
// here tolerates, so callers do not have to branch.
func New(cfg *compaction.Config, svc session.Service) *Runtime {
	if cfg == nil {
		return nil
	}
	return &Runtime{config: cfg, sessionService: svc}
}

// Config returns the compaction config.
func (rt *Runtime) Config() *compaction.Config {
	if rt == nil {
		return nil
	}
	return rt.config
}

// SessionService returns the service that persists summaries.
func (rt *Runtime) SessionService() session.Service {
	if rt == nil {
		return nil
	}
	return rt.sessionService
}

// MarkCompacted records that a compaction ran during this invocation.
func (rt *Runtime) MarkCompacted() {
	if rt == nil {
		return
	}
	rt.compacted.Store(true)
}

// AlreadyCompacted reports whether a compaction ran during this invocation.
//
// The two strategies are independent triggers on the same history, so without
// this a turn that crossed the token threshold mid-flight would be summarized
// again by the sliding window the moment it ended, paying for a second model
// call to re-summarize what was just summarized. The reference implementation
// avoids it by evaluating the two in one place and returning early; the same
// effect is reached here by remembering, since the two run at different points
// in the turn.
func (rt *Runtime) AlreadyCompacted() bool {
	return rt != nil && rt.compacted.Load()
}

// Configured reports whether compaction is enabled for this run.
//
// Prompt assembly gates on this rather than simply honouring any compaction
// record it finds. A record instructs the prompt builder to drop a range of
// history and substitute content in its place, so acting on one that this
// runner did not ask for would turn a stored field into an erase-and-inject
// primitive, available even to an application that never enabled compaction.
func (rt *Runtime) Configured() bool {
	return rt != nil && rt.config != nil
}

// Enabled reports whether rt can actually run a tail-retention compaction.
func (rt *Runtime) Enabled() bool {
	return rt != nil && rt.sessionService != nil && compactioninternal.HasTailRetention(rt.config)
}

// ToContext returns a context carrying rt.
func ToContext(ctx context.Context, rt *Runtime) context.Context {
	return context.WithValue(ctx, runtimeCtxKey, rt)
}

// FromContext returns the [Runtime] carried by ctx, or nil when compaction is
// not configured.
func FromContext(ctx context.Context) *Runtime {
	rt, ok := ctx.Value(runtimeCtxKey).(*Runtime)
	if !ok {
		return nil
	}
	return rt
}

type ctxKey int

const runtimeCtxKey ctxKey = 0

// AllowAt reports whether a compaction at this prompt size is worth attempting.
//
// It declines when the previous compaction in this invocation did not bring the
// prompt below the size that triggered it. That is the case where compacting
// cannot help: the retained tail alone already exceeds the threshold, so every
// model call crosses it again and each one pays for a summarizer call that
// changes nothing. Measured before this existed: six summarizer calls inside a
// single seven-call invocation.
//
// A prompt that has actually shrunk, or grown past where it was, is allowed
// through, so a long turn can still compact more than once when doing so helps.
func (rt *Runtime) AllowAt(tokens int) bool {
	if rt == nil {
		return false
	}
	last := rt.lastCompactionTokens.Load()
	return last == 0 || int64(tokens) < last
}

// RecordAt notes the prompt size that triggered a compaction.
func (rt *Runtime) RecordAt(tokens int) {
	if rt == nil {
		return
	}
	rt.lastCompactionTokens.Store(int64(tokens))
}
