# Changelog

All notable changes to ARES Core are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/) (pre-1.0: minor
versions may include breaking changes).

## [Unreleased]

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
- README "Build your own app in <100 LOC" tutorial — 77-line worked
  example with three phases (two framework-provided, one user-written)
  showing the minimum viable ARES app shape. Compile-verified against
  the live framework before commit.

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

[Unreleased]: https://github.com/Fheyalabs/ARES-core/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Fheyalabs/ARES-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Fheyalabs/ARES-core/releases/tag/v0.2.0
