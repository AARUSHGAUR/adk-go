---
name: adk-v2-migration
description: Migrate a Go program from ADK Go 1.x to 2.x — the `/v2` module path, the unified `agent.Context`, the new `session.NewEvent` signature, the changed `Event` JSON shape, and the changes that compile but behave differently. Use when upgrading a project off `google.golang.org/adk`, when a build breaks on `agent.ToolContext` or `agent.CallbackContext`, when stored 1.x sessions have to be read by 2.x, or when asked what 2.0 breaks.
---

# Migrating ADK Go 1.x to 2.x

Most 1.x programs need the import path changed and little else: **the workflow
graph engine is not mandatory**. `runner` wraps any root agent in a synthetic
`START -> node` graph (`runner/run_node.go:84`), so a plain `LlmAgent` program
keeps working — `examples/quickstart` differs between the two branches only in
the import prefix and a model name. Adopt `workflow/` when you want it, not to
compile.

Work in this order. Steps 1 and 2 are mechanical; step 3 is where the real risk
is, because none of it fails the build.

## 1. Module path

`google.golang.org/adk` → `google.golang.org/adk/v2`, and Go 1.25 → 1.26.

```bash
go get google.golang.org/adk/v2
rg -l '"google\.golang\.org/adk/' --glob '*.go' | xargs sed -i 's|google\.golang\.org/adk/|google.golang.org/adk/v2/|g'
go mod tidy
```

Check the result for a doubled `/v2/v2/`, and drop the old `require` line.

## 2. What no longer compiles

- **`agent.CallbackContext` and `agent.ToolContext` are gone**, merged into one
  `agent.Context` (`agent/context.go:142`). This is the one adoption a v1
  program cannot avoid. It hits every callback signature —
  `Before/AfterAgentCallback` (`agent/agent.go:130`), the six model and tool
  callbacks on `llmagent.Config` (`agent/llmagent/llmagent.go:372-411`) — and
  every function tool: `functiontool.Func[TArgs, TResults]` is now
  `func(agent.Context, TArgs) (TResults, error)`
  (`tool/functiontool/function.go:72`).
- **`tool.Context` and `tool.NewToolContext` are gone** — the whole `tool/context.go`
  file. Use `agent.Context`.
- **`session.NewEvent` takes a context first**: `NewEvent(invocationID string)`
  → `NewEvent(ctx context.Context, invocationID string)`
  (`session/session.go:230`). The ID and timestamp now come from the `platform`
  package, so a clock or UUID provider on the context makes events
  replay-deterministic. Pass the `ctx` already in scope — an `agent.Context`,
  a tool's context, a request context, `t.Context()` in tests. Do not reach for
  `context.Background()` mid-chain.
- **`session.NewEventWithContext` is removed** (it existed in v1 as the
  context-taking variant). Rename those call sites to `NewEvent`.
- **`artifact.ArtifactVersion.CreateTime` is a `time.Time`**, not a `float64`
  (`artifact/service.go:274`).

Find the work:

```bash
rg -n 'agent\.(ToolContext|CallbackContext)|tool\.(Context|NewToolContext)' --glob '*.go'
rg -n 'NewEventWithContext|session\.NewEvent\(' --glob '*.go'
```

## 3. What compiles but behaves differently

- **A custom tool that kept the old context type reports as "tool not found".**
  The runtime reaches a tool's `Run` and `ProcessRequest` through type
  assertions, and both contracts now name `agent.Context`. A tool still written
  against `agent.ToolContext` compiles — it satisfies `tool.Tool`, which did not
  change — but fails the assertion, so a call to it comes back as tool-not-found
  (`internal/llminternal/base_flow.go:1174`) even though it is registered, and
  the request fails with "does not implement RequestProcessor" (`base_flow.go:743`).
  Diagnose that symptom by checking the signature, not the registration.
- **`llmagent.Config.Mode` is new, and a root agent must be a chat agent.**
  An unset mode becomes `ModeChat`, so a v1 program is fine; but a root
  `LlmAgent` with any other mode is now a hard error at run time
  (`runner/runner.go:218`). Task mode also auto-installs its own tools.
- **Gemini no longer injects a placeholder user turn** when `Contents` is empty.
  Code that relied on that padding now sends a genuinely empty request.
- **`model.LLMResponse` gained `json:",omitempty"` tags** — anything that
  serialized a response and matched on key names sees new spelling.

## 4. Stored sessions

`session.Event` in v1 carried **no JSON tags at all**, so it serialized under Go
field names: `ID`, `Timestamp`, `InvocationID`, `LongRunningToolIDs`. In 2.x
every field is tagged (`session/session.go:98`), so the same event now writes
`id`, `timestamp`, `invocationId`, `longRunningToolIds`. Five fields are also
new: `IsolationScope`, `Routes`, `RequestedInput`, `Output`, `NodeInfo`.

- Storing events as opaque JSON blobs? Nothing to do for the new fields, but the
  **key renames still change what your rows contain**, and a 1.x reader pointed
  at 2.x data finds none of the fields it expects.
- Storing events in rigid columns? Add the five, and map the renamed keys.
- `session.Service` itself is unchanged — no method to reimplement. The work is
  entirely in what gets persisted.
- `Event.UnmarshalJSON` in 2.x accepts a numeric timestamp, which is what
  adk-python writes, so cross-runtime sessions read back.

The 2.0 page at <https://adk.dev/2.0/> is the official list, and it is wrong on
one detail: it states that `Routes`, `RequestedInput` and `Output` have no JSON
tag. They do — `routes`, `requestedInput`, `output`. It also does not mention
the tags added to the pre-existing fields, which is the larger migration.

## 5. What 2.x adds, all optional

| Package | What it is |
|---|---|
| `workflow/` | Graph engine: nodes, edges, routing, fan-out/fan-in, HITL pauses. Examples under `examples/workflow/`. |
| `agent/workflowagent` | An `Agent` built from a graph, for use anywhere an agent goes. |
| `llmagent` modes | `ModeChat`, `ModeTask`, `ModeSingleTurn` — collaborative multi-agent setups. |
| `auth/` | Credentials and auth providers for outbound calls. |
| `agentregistry/` | Client for Google Cloud Agent Registry: discover A2A agents and MCP servers, resolve them into agents and toolsets. |
| `model` registry | `model.Register` / `model.NewLLM` resolve a model by name pattern. Nothing self-registers. |
| `model/openaimodel` | OpenAI-compatible backend. |
| `plugin/agentanalytics` | Analytics plugin; a separate Go module, so it needs its own `require`. |

Unchanged, and worth knowing before you go looking: `agent.Agent`, `agent.New`,
`tool.Tool`, `tool.Toolset`, `model.LLM`, `gemini.NewModel`, `runner.Config`,
`runner.New`, `session.Service`, `memory.Service`, `artifact.Service`, the
`cmd/launcher` interfaces, and all three `agent/workflowagents/*` packages.

## Verify

```bash
go build ./...
go vet ./...
go test ./...
rg -n '"google\.golang\.org/adk/[^v]' --glob '*.go'   # any 1.x import left
```

Then exercise one real run, not just the build: the tool-context regression in
step 3 is invisible to the compiler and to any test that does not call the tool.
