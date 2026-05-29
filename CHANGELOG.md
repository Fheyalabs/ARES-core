# Changelog

All notable changes to ARES Core are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/) (pre-1.0: minor
versions may include breaking changes).

## [Unreleased]

### Roadmap (Fheya-app-side, recorded here so ARES-core knows what its consumer needs)

The Fheya app at `Fheyalabs/ARES.git` is the load test for ARES-core
v1.0. Three pieces of work blocking real homelab traffic — none of
which require ARES-core API changes, but ARES-core's `[Unreleased]`
records them so the framework knows what its primary consumer is
moving toward.

- **Post-session memory cleanup.** Orchestrator currently leaks
  per-session FHE artifacts (`scoringInputs`, `profiles`, accumulator
  buckets) until container restart. Audit OP-CAP-6. Fheya-app PR.
- **Nightly amortized keygen.** Threshold keygen is 95% of
  `n=6` dim=128 session wall-clock. Proposal:
  `wiki/summaries/nightly-keygen-batch-orchestrator-2026-05-19.md` —
  split orchestration into cohort-formation / nightly-keygen /
  daytime-scoring subsystems. Uses ARES-core's existing
  `keygen.PreSharedKeygen` primitive; no framework changes required.
- **Self-hosted CI runner on the homelab.** Free GitHub-hosted
  runners can't carry full `n=6` dim=128 keygen; Fheya's end-to-end
  lane needs `runs-on: [self-hosted, fheya-homelab]`. ARES-core's CI
  stays on hosted runners; Fheya's CI gets a separate self-hosted
  lane.

### CI

- OpenFHE CI lane now installs to `/opt/openfhe` (instead of
  `/usr/local`) and caches that prefix only. Three concrete wins:
  cache restore drops from ~4 min to ~2 s, the build step is reliably
  skipped on cache hit (was incrementally rebuilding before), and a
  `concurrency: openfhe-${{ github.ref }}` group prevents parallel
  pushes from racing on the cache key. Warm-run wall time drops from
  14-18 min to ~3 min.

### Docs

- `docs/migrations/fheya-server.md` records the durable plan for
  retiring the historical `fheya-server` REST server in favor of an
  ARES-core + Fheya app composition. Surface map for all 25 legacy
  endpoints, six PR-sized migration steps, and the hard preconditions
  blocking most of the work (ARES-core 1.0 stable + Fheya app Phase
  1b/2/D real implementations).

## [0.5.0] — Unreleased

### Added

- **`pkg/ares/onion`** — client-side slot-anonymization crypto:
  X25519 ECIES envelopes (HKDF-SHA256 `ares_onion_v1` + AES-256-GCM,
  Python wire-parity), SC-2-correct onion construction
  (`BuildOnion`/`PeelBatch` with self-layer + ciphertext-memory-match
  identification), and a deterministic coordinator-free
  `SlotPermutation`. Package godoc documents the SC-7 collusion bound
  (certain deanonymization requires `k >= N-2` colluders; 50% floor at
  `k = N-3`). Foundation for the canonical onion-shuffle phases (next).
- **`pkg/ares/phase/anon`** — composable onion-shuffle phases for
  inter-participant slot anonymity: `PhaseGShuffle` (sequences the
  peel rounds, GOSSIP→VERIFYING) and `PhaseGVerify` (accumulates
  ephemeral-key-signed slot submissions and assembles + lineage-commits
  the ordered slot list, VERIFYING→caller's next state), plus a
  `Participant` client driver. Verification is lineage-native — slot
  submissions are SC-10 DAG nodes signed by ephemeral per-slot keys, so
  the relay/other participants cannot tamper without an attributable
  mismatch, and no participant learns another's slot→identity mapping.
- **`examples/voting` `PipelineWithShuffle`** — worked adopter of the
  onion-shuffle primitive; demonstrates `PhaseGShuffle` + `PhaseGVerify`
  composed over the GOSSIP→VERIFYING arc on a non-FHE pipeline so the
  election authority cannot link an anonymized ballot slot to its voter.

## [0.4.1] — 2026-05-28

Developer-experience patch. No new protocol features, no API breaks.
Cuts the consumer-facing rough edges flagged during the v0.4.0
implementation review so the next consumer integration (Fheya
app's opportunistic ComposeWith migration; external app authors
adopting the framework) reads well-documented, classifiable
errors.

### Added

- **Failure-type sentinels** in `pkg/ares/phase`. Four sentinel
  errors apps use to branch retry / penalty / report-bug policy
  via `errors.Is(err, phase.ErrXxx)` without string-matching:
  - `phase.ErrTransient` — retryable (backend unreachable, lock
    contention, transient network).
  - `phase.ErrPermanent` — non-retryable (config, schema,
    invariant breach, caller misuse).
  - `phase.ErrAppAttributable` — counterparty caused (tampered
    payload, false mismatch claim, malformed commit).
    `errors.As(err, &mismatchErr)` still recovers the typed
    `*lineage.MismatchError` underneath.
  - `phase.ErrFrameworkBug` — unexpected internal condition
    (apps surface, do not silently recover).
- **`phase.SetHookPanicLog(io.Writer) io.Writer`** — process-init
  override for the destination `fireFailureHook` writes to when
  an app-registered `LineageFailureFn` panics. Default
  `os.Stderr`. Pass `io.Discard` to silence; pass a
  `*bytes.Buffer` in tests to capture and assert.

### Changed

- **Every framework-level error from the `SessionRunner` public
  API is now classified with a sentinel.** Apps that previously
  string-matched error messages now branch via `errors.Is`. The
  underlying typed errors (e.g. `*lineage.MismatchError`) remain
  recoverable via `errors.As`. See `errors_classify_test.go` for
  the full classification table.
- **`fireFailureHook` panic-recovery logs to stderr** instead of
  silently swallowing the recovered value. The runner still
  recovers (so a buggy hook doesn't crash the runner), but the
  misbehavior is now observable at runtime.

### Docs

Five load-bearing-but-implicit behaviors now surface in the public
godoc rather than only in the implementation:

- `ComposeWith` auto-commit exemption rules — non-`[]byte` runtime
  values are silently skipped (apps must marshal struct types
  before `ctx.Set`); `NoLineage: true` Provides outputs are
  intentionally skipped.
- `BeginSession` does NOT cascade past the initial phase even if
  `CheckComplete` returns true. The pause exists so
  `SessionTrigger` implementations can seed canonical context
  entries before the second phase's `Enter` runs.
- `AdvanceToState` behavior on the three corner cases:
  target == current (no-op), target ∈ InternalStates of current
  phase (no-op), target == `StateNone` (rejected — callers should
  `EndSession` explicitly).
- `HandleMessage` vs `HandleLineageMessage` on a `ComposeWith`-built
  runner — `HandleMessage` works but skips lineage verification.
- `BuildMismatchClaim`: the `role` parameter is accepted but NOT
  propagated to the resulting `DAGNode` (whose `Role` is
  hardcoded to `"mismatch-claim"` so receivers can distinguish a
  claim from a real commit). Documented as a known v0.5.0
  follow-up rather than fixed in v0.4.1 (would be a behavior
  change to v0.4.0 API surface).

Every public-method godoc now also lists the sentinels its
errors classify with so apps know which branch to take without
reading the implementation.

### Tests

- Per-app **bitflip tests at every lineage-protected stage**
  (15 new subtests across the 4 reference apps). Each subtest
  flips a single payload bit between `lineage.Commit` and
  `HandleLineageMessage` and asserts `*MismatchError{Field:"PayloadHash"}`
  at every phase boundary the framework auto-binds. Strong-form
  SC-10 demonstration: not just "lineage detects tampering at
  the bid stage" but "every stage and any single-bit flip."
- New **helper+lineage combined tests** (5 new subtests across
  the 3 FHE reference apps). `PipelineWithLineageAndHelper`
  constructors had zero prior coverage — a constructor-arg-order
  bug would have shipped silently. Now exercised end-to-end
  with a live OpenFHE helper subprocess.

## [0.4.0] — 2026-05-28

**SC-10 Ciphertext Lineage Primitive** — framework-level Merkle DAG
binding every byte payload at every phase boundary. Closes
ultrareview findings C1 (SC-5 `C_emb` undefined) and substantially
addresses H2 (Phase 2 ciphertext-binding gap) for the framework code
path. See ARES Spec v2.5 §SC-10 for protocol-level documentation;
`pkg/ares/lineage/README.md` and `pkg/ares/sign/README.md` for the
Go-side API.

### Added

- **`pkg/ares/sign/`** — new package. Pluggable `Signer` interface;
  `Ed25519Signer` default (crypto/ed25519 from stdlib). HSM-backed
  and post-quantum schemes substitutable via the interface.
- **`pkg/ares/lineage/`** — new package. `DAGNode`, `Commit`,
  `Verify`, `Store` interface, `InMemoryStore` default; structured
  `*MismatchError` for failure forensics. Idempotent `Append`;
  `WalkSession` returns `iter.Seq2[DAGNode, error]` for lazy
  iteration.
- **`phase.ContextKeyType.NoLineage`** — opt-out field on
  context-key declarations. Default `false` (lineage enforced). Set
  `true` for ephemeral or public outputs that don't need
  cryptographic binding. Auditable from one place: grep
  `"NoLineage: true"`.
- **`phase.ComposeWith(phases, opts...)`** — new constructor for
  lineage-enabled pipelines. Options: `WithSigner` (required),
  `WithPeerVerifiers` (required for multi-party), `WithStore`
  (default `InMemoryStore`), `WithLineageFailureHook`.
- **`phase.LineageFailureEvent` + `phase.LineageFailureFn`** —
  structured callback for app-level penalty handlers (Fheya's
  brownie deductions, etc.). Kinds: `"mismatch-confirmed"`,
  `"mismatch-false-claim"`.
- **`SessionContext.LineageDAG()`** — read-only `iter.Seq[DAGNode]`
  over the session's DAG nodes. Empty on `Compose`-built runners.
- **`SessionRunner.HandleLineageMessage(...)`** — transport-layer
  entry point that verifies + persists inbound lineage before
  dispatching to `Phase.OnMessage`. Compose-built runners fall
  through to the legacy `HandleMessage` path.
- **`SessionRunner.BuildMismatchClaim(...)` /
  `SessionRunner.ReportFalseLineageClaim(...)`** — framework hooks
  for the transport layer's mismatch cross-verification flow.
- **`transport.WSMessage.Lineage *lineage.DAGNode`** — required
  field on v2 frames. Full signed `DAGNode` rides inline with the
  payload (no separate commit frame, no ordering window).
- **`transport.WireProtocolVersionLineage = "2"`** — new wire
  version for ComposeWith-built pipelines. Existing
  `WireProtocolVersion = "1"` preserved for Compose-built
  pipelines.
- **`transport.ArtifactStore.PutContent` /
  `transport.ArtifactStore.GetContent`** — content-addressed methods
  alongside the existing app-keyed API. `GetContent` detects
  in-memory corruption via re-hash, returns `ErrCorrupted` on
  mismatch.
- **`transport.ValidateInboundMessage`** — hub strict-mode validator.
  v2 frames missing `Lineage` are rejected; unknown versions
  rejected; v1 frames accepted regardless of `Lineage` (backward
  compat).
- **`cgo.RoundTripCiphertext`** (`-tags openfhe`) — exported wrapper
  for the OpenFHE serialization golden-hash test
  (`pkg/ares/crypto/cgo/serialization_golden_test.go`) which guards
  the OpenFHE 1.5.1 pin against drift via a checked-in fixture in
  `pkg/ares/crypto/cgo/testdata/`.
- Reference apps migrated:
  - `examples/sealed_bid_auction/` — `PipelineWithLineage` +
    `PipelineWithLineageAndHelper` + tamper smoke test.
  - `examples/ride_share/` — same shape.
  - `examples/recurring_cohort_ranking/` —
    `FormationPipelineWithLineage` +
    `WeeklyPipelineWithLineage` (both take a shared
    `lineage.Store`) + tamper smoke test on the standalone-
    composable formation pipeline.
  - `examples/voting/` — `PipelineWithLineage` + tamper smoke
    (demonstrates SC-10 protects non-FHE byte payloads too).
  - Legacy `Pipeline()` / `PipelineWithHelper()` / `WeeklyPipeline()`
    / `FormationPipeline()` constructors preserved unchanged.

### Compatibility notes

- Existing `phase.Compose(phases...)` call sites unchanged; emit v1
  wire frames; lineage stays off. No breakage for v0.3.x consumers.
- Applications opt into lineage by switching to
  `phase.ComposeWith(...)`. Fail-fast at construction time if
  required options (Signer; PeerVerifiers for multi-party) are
  missing.
- WSMessage v2 frames are accepted by the hub iff `Lineage` is
  non-nil; v1 frames continue working as before.

### Developer-experience follow-ups (deferred to v0.4.x patches)

The first review pass of the v0.4.0 implementation flagged several
DX items that don't block the release but are tracked for a
dedicated pass before the Fheya migration:

- Tighten every framework-layer error message: include phase name,
  context key, root cause; reject generic phrasing.
- Distinguish failure types (transient / permanent /
  app-attributable / framework-bug) via concrete types or sentinels
  so apps can branch policy without string-matching.
- Audit every exported symbol for godoc coverage (what / when /
  when-not / parameters / returns / failure modes).
- Surface load-bearing implicit behaviors explicitly (e.g.,
  non-`[]byte` Provides outputs silently skipped from auto-commit).
- Add stderr logging to `fireFailureHook`'s `recover()` so buggy
  app hooks are visible at runtime, not just postmortem.

## [0.3.1] — 2026-05-19

Patch release: post-launch hardening from the 2026-05-19 audit
follow-up items, plus a "build your own app" tutorial in the README.

### Security

- **Replay protection.** Per-`(session_id, pseudonym, message_type)`
  monotonic sequence-number tracking in `transport.Hub`. Frames whose
  `WSMessage.Seq` is `<=` the highest accepted for the same tuple are
  silently dropped with a `[hub] replay drop` log line; the connection
  stays open. Empty / zero `Seq` bypasses the check for backward
  compatibility with pre-v0.3 clients.

### Added

- `ARESSession.connect(..., ssl_context=...)` accepts an
  `ssl.SSLContext` (or `False` to disable verification, or `None` to
  use the system default for `wss://`). Docs in
  `clients/python/README.md`.
- `pkg/ares/crypto/cgo/bridge.go` documents the "guard before
  `&slice[0]`" invariant + ships `requireNonEmptyBytes` helper for
  future contributors.
- README "Build your own app" tutorial — five-phase worked example
  (Invite + PlaintextKeygen + Collect + Announce + runner) showing the
  minimum viable ARES app shape with one state arc per phase.
  Compile-verified against the live framework before commit.

## [0.3.0] — 2026-05-19

First public release. v0.2 was a private snapshot of the framework
extraction; v0.3 cleans it up, removes app-specific code from the
framework core, and adds the OSS-launch hygiene.

### Security

- **WebSocket Origin allow-list** (`transport.Config.AllowedOrigins`).
  Production deployments now reject browser origins that aren't on the
  list. Non-browser clients (Go / Python) that omit the `Origin` header
  are unaffected. Legacy `NewHub` keeps the permissive default for the
  example apps.
- **Inbound WebSocket message size cap** (`Config.MaxWSMessageSize`,
  default 32 MiB). Replaces gorilla's default 512 KiB while bounding
  peer-driven memory.
- **Artifact PUT body cap** (`Config.MaxArtifactSize`, default 64 MiB).
  Oversized uploads now return `413 Request Entity Too Large` instead
  of silently allocating unbounded memory.
- **SSE log-stream newline-injection fix.** `writeSSE` now splits log
  lines on `\n` and emits each as a separate `data:` line. Optional
  `Config.DebugLogsAuth` gate added; default behavior unchanged
  (suitable for trusted reverse-proxy deployments only).
- **`ARES_ENV=production` refuses `AllowDevBypass=true`.** Hard
  configuration error at `NewService` time when the environment
  declares production and dev bypass is enabled.
- **Keygen-topology composition guard.** `phase.Compose` now rejects
  pipelines that wire `SinglePartyKeygen` (or any keygen tagged
  `topology=single_party` / `plaintext`) into a phase that requires
  `topology=threshold` (e.g. `Phase3ThresholdDecrypt`). Prevents an
  app author from silently substituting a server-trusted keygen into a
  pipeline whose decrypt phase assumes threshold semantics.
- **WSMessage wire-protocol versioning.** `WSMessage.Version` field +
  `WireProtocolVersion = "1"` constant. Frames with a declared major
  that doesn't match are dropped at the hub. Empty version accepted
  for backward compatibility with pre-v0.3 clients.

### Added

- Apache-2.0 LICENSE + `SPDX-License-Identifier` header on every source file.
- `pkg-config/openfhe.pc.in` template for installs that prefer pkg-config.
- `OpenFHEVersion()` Go API and `--version` flag on the helper binary.
- `Client.Version()` returns the helper's linked OpenFHE library version;
  `Client.Start()` warns to stderr if the version doesn't match
  `SupportedOpenFHEVersionPrefix` (`v1.5.`).
- `examples/voting/`: anonymous tally reference app using
  `PlaintextKeygen` + sum-weighted aggregation (new fourth reference
  app demonstrating non-MPC keygen).
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  GitHub issue / PR templates.
- CI workflows: Go-only lane (`.github/workflows/go.yml`) and
  OpenFHE-container lane (`.github/workflows/openfhe.yml`).

### Changed

- **Breaking:** `phase.NewSessionRunner(...)` renamed to `phase.Compose(...)`.
- **Breaking:** Per-app constructors renamed:
  - `auction.NewSealedBidAuctionRunner()` → `auction.Pipeline()`
  - `auction.NewSealedBidAuctionRunnerWithHelper()` → `auction.PipelineWithHelper()`
  - `rideshare.NewRideShareRunner()` → `rideshare.Pipeline()`
  - `rideshare.NewRideShareRunnerWithHelper()` → `rideshare.PipelineWithHelper()`
  - `cohort.NewWeeklyRankingSession()` → `cohort.WeeklyPipeline()`
  - `cohort.NewCohortFormationRunner()` → `cohort.FormationPipeline()`
- **Breaking:** Package renames (directory names unchanged):
  - `package sealedbidauction` → `package auction`
  - `package recurringcohortranking` → `package cohort`
- **Breaking:** Context-key renames in `pkg/ares/phase/defaults`:
  - `CtxCipherWinnerPackage` → `CtxResultCiphertext` (`"ct_winner_pkg"` → `"result_ct"`)
  - `CtxWinnerPackage` → `CtxResultBytes` (`"winner_pkg"` → `"result_bytes"`)
- Python smoke scripts renamed by crypto layer:
  - `*_homelab_smoke.py` → `*_openfhe_smoke.py` (real CKKS)
  - `*_config.py` → `*_stub_smoke.py` (placeholder bytes)
- `DeserializeCiphertext` in the C++ wrapper now verifies the
  deserialized ciphertext's `CryptoContext` matches the local context
  and emits a clear stderr message on mismatch, replacing the opaque
  `rc=-100` error.
- cgo OpenFHE include + library paths split into per-OS files
  (`bridge_darwin.go`, `bridge_linux.go`) covering `/usr/local`,
  `/opt/homebrew`, and `/usr/local/lib64`.

### Removed

- **Breaking:** `defaults.NewARESDefaultRunner()` deleted. ARES-core no
  longer ships an opinionated default pipeline; applications compose
  their own via `phase.Compose(...)`.
- **Breaking:** Matchmaking-shaped phases removed from
  `pkg/ares/phase/defaults`:
  `Phase1bEncryptedSubmit`, `Phase2FHEScoring`, `PhaseGOnionShuffle`,
  `PhaseG2Verification`, `PhaseDAnonymousBroadcast`. These were
  Fheya-app-specific and moved conceptually to consuming apps.
- **Breaking:** Fheya-only context keys removed from defaults:
  `CtxOnionRoundsComplete`, `CtxContribHashes`, `CtxMacSeeds`,
  `CtxSessionMacKey`, `CtxEncryptedInputs`, `CtxPhaseDSchedule`.
  Consuming apps must declare their own equivalents.

### Fixed

- Partial-decrypt placeholder bug in `*_openfhe_smoke.py`: smokes were
  sending `"pd-<name>"` instead of a real partial ciphertext, blocking
  sessions from reaching the SETTLED state. Now run a real
  `helper.partial_decrypt` against a shared target ciphertext.
- Cross-platform OpenFHE build (was hardcoded to `/usr/local`, broke on
  Apple Silicon Homebrew and on RHEL/Fedora's `/usr/local/lib64`).
- OpenFHE version mismatch between client and server now surfaces with
  a clear error at deserialization time instead of as `rc=-100`.

## [0.2.0] — 2026-05-17

Initial framework-extraction snapshot (private). Split ARES into a
generic framework (`Fheyalabs/ARES-core`) and a Fheya app
(`Fheyalabs/ARES`). 30+ tests passing across both repos.

[Unreleased]: https://github.com/Fheyalabs/ARES-core/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/Fheyalabs/ARES-core/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.3.2...v0.4.0
[0.3.1]: https://github.com/Fheyalabs/ARES-core/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Fheyalabs/ARES-core/releases/tag/v0.2.0
