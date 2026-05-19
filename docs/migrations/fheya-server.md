# Migrating `fheya-server` onto ARES-core

Plan for retiring the historical `fheya-server` repo
(`/Users/hardik/Fheya/repos/fheya-server`) by re-implementing its
3-party threshold-FHE proximity-matching surface on top of ARES-core
and the modern Fheya app at `Fheyalabs/ARES.git`.

This is a multi-PR effort. The doc enumerates the steps, identifies
preconditions, and records what's known about both codebases so the
next contributor can pick it up without re-discovering the surface.

## Status: planning, not started

No `fheya-server` code has moved yet. `fheya-server/go.mod` carries no
ARES-core dependency, so the migration is **greenfield** rather than a
mechanical port — the legacy REST surface and the ARES-core WebSocket
surface don't speak the same wire protocol.

## Why migrate

The legacy `fheya-server` (~2,370 lines of Go + ~equivalent Python)
duplicates roughly 70 % of what ARES-core + the Fheya app at
`Fheyalabs/ARES.git`'s `apps/fheya/` now provide:

- Its own OpenFHE cgo wrapper (`internal/fhe/fhe.go`, 391 lines).
- Its own threshold-keygen orchestration (handlers
  `handleSubmitKeyShare`, `handleFinalizeKeys`,
  `handleSubmitMultEvalKey`).
- Its own scoring polynomial (`internal/server/scoring.go`).
- Its own threshold-decrypt fusion (`handleSubmitPartialDecrypt`,
  `handleGetDecrypted`).
- Plus Python parity server kept in lockstep.

ARES-core covers the framework concerns; `apps/fheya/` covers the
Fheya-shaped phases. The legacy server should consume both rather
than maintain its own copies.

## Preconditions (hard blockers)

The audit at `wiki/summaries/ares-core-review-2026-05-19.md` §3 lists
two hard preconditions before code can land:

1. **ARES-core 1.0 stable.** API is still pre-1.0; minor versions can
   break. Migration code shouldn't pin to a moving target. Earliest
   eligible target is `v1.0.0`.
2. **Fheya app `apps/fheya/phases/` Phase 1b / Phase 2 / Phase D
   implementations are real, not stubs.** Without those, the
   migration has nothing to call into for scoring or post-result.

Both blockers live in this repo (or the Fheya repo) — addressing them
unlocks the migration but is itself substantial work.

## Surface map: legacy → framework

The legacy server registers these endpoints in
`internal/server/handlers.go:23`. Each maps onto an ARES-core phase or
a Fheya app artifact:

| Legacy endpoint | Modern equivalent | Notes |
|---|---|---|
| `POST /join` | `Phase1aSessionInitiation` invitation | Server-side trigger seeds `CtxParticipants`; clients open WS. |
| `POST /submit_key_share` | `Phase0aThresholdKeygen` consumed `keygen.share` | Same protocol, different transport. |
| `POST /finalize_keys` | Phase 0a's `CheckComplete` + `Exit` | Server fuses internally; no separate endpoint needed. |
| `POST /submit_mult_eval_key` | Phase 0a eval-key round 2 | Subsumed by the threshold-keygen phase. |
| `GET /combined_eval_key` | `CtxEvalKeys` in session context | Clients receive via WS push, not poll. |
| `GET /joint_public_key` | `CtxCollectivePublicKey` | Same as above. |
| `POST /start_match` | Trigger `POST /admin/sessions` | The session-service `Trigger` interface. |
| `POST /submit_distance` | `Phase1bEncryptedProfileSubmit` (Fheya app) | **Blocked on Fheya app stub.** |
| `POST /compute_nearest` | `Phase2FheyaScoring` (Fheya app) | **Blocked on Fheya app stub.** |
| `GET /get_result` | `CtxResultCiphertext` broadcast | Pushed via `scoring.complete` WS frame. |
| `POST /submit_partial_decrypt` | `Phase3ThresholdDecrypt` consumed `decrypt.partial` | Same protocol, different transport. |
| `GET /get_decrypted` | Phase 3's `CtxResultBytes` broadcast | Pushed via `decrypt.complete`. |
| `POST /submit_match_proof` | App-specific verification phase | Not in core; lives in `apps/fheya/`. |
| `POST /send_chat`, `GET /get_chat` | `PhaseDFheyaAnonymousBroadcast` | **Blocked on Fheya app stub.** |
| `GET /status`, `/ping`, `/slot_map`, `/commitments` | `transport.AdminHandlers` | Already provided by ARES-core. |

## Suggested PR sequence (6 steps)

Each step is roughly one PR-sized chunk.

### Step 1 — Replace `internal/fhe/` with `pkg/ares/crypto/cgo` (in fheya-server)

Independent of preconditions. The legacy `internal/fhe/fhe.go` (391
lines) is a thin cgo wrapper; ARES-core's
`pkg/ares/crypto/cgo/bridge.go` does the same thing with more ops and
maintained tests.

- Add `Fheyalabs/ares-core` to `fheya-server/src/go-server/go.mod`.
- Replace each `fhe.Context.X` callsite in `internal/server/handlers.go`
  with the equivalent `openfhe.X` call from ARES-core.
- Delete `internal/fhe/`.
- Run existing fheya-server tests to confirm wire-level parity.

Scope: ~1 day. **Unblocked.**

### Step 2 — Convert HTTP handlers into ARES phase adapters

Requires preconditions met.

- Stand up a `phase.SessionRunner` inside fheya-server.
- For each HTTP handler that orchestrates a phase (`/submit_key_share`,
  `/submit_distance`, `/submit_partial_decrypt`), translate the HTTP
  request into a `WSMessage`-shaped struct and feed it to the runner
  via a thin HTTP→runner shim.
- Keep the REST surface bit-compatible so existing clients (iOS,
  Android, Python parity) don't break.
- Eventually expose a parallel WS surface for new clients.

Scope: ~1-2 weeks. **Blocked on preconditions.**

### Step 3 — Drop the local scoring polynomial

Requires `Phase2FheyaScoring` to be a real implementation in the
Fheya app, not a stub.

- Delete `internal/server/scoring.go`.
- Route `/compute_nearest` through the framework's Phase 2.
- Verify the polynomial coefficients in the Fheya app's `Phase2FheyaScoring`
  match the legacy server's (no protocol divergence).

Scope: ~3 days. **Blocked on Fheya app §2 critical gap.**

### Step 4 — Replace threshold-decrypt handlers

- Wire `/submit_partial_decrypt` + `/get_decrypted` to
  `defaults.Phase3ThresholdDecrypt`.
- Delete the local fusion code in `handleGetDecrypted` (~50 lines).

Scope: ~2 days. **Lightly blocked** (Phase 3 is stable in ARES-core
v0.3.1; the work is mechanical handler conversion).

### Step 5 — Keep app-only concerns where they are

These don't move into ARES-core:

- Account REST (`/account/*`).
- Nonce-commitment (`/commitments`).
- Encrypted chat relay (`/send_chat`, `/get_chat`) — Fheya-specific.
- Push notifications.
- Deploy scripts.

Scope: nothing to do beyond confirming they still build.

### Step 6 — Retire the Python parity server

After Go parity is proved against the migrated server:

- Mark `fheya-server/src/python/` as deprecated.
- Final Python release captures the last-known wire shape for archive.
- Remove from CI; tests stay frozen in `archive/`.

Scope: ~1 day. **Final step.**

## Open design questions

1. **Greenfield vs in-place.** My read is **greenfield is safer**:
   stand up a new `fheya-server-v2` package importing ARES-core, drive
   the legacy clients against it via a feature flag, retire the old
   server once parity is proven. The audit said the legacy REST surface
   is thinly tested; rewriting in-place risks silent behavior drift.
   But you may want to preserve git history — in-place keeps that.
2. **REST vs WS for legacy clients.** iOS / Android clients today use
   REST + polling. Switching them to WS is a separate migration. The
   adapter approach (HTTP→runner) preserves REST during migration.
3. **Python parity timeline.** Worth keeping in parallel during the
   migration so cross-implementation behavior bugs surface early?
   Or retire it once Go parity is proved?

## Cross-references

- Audit page: `wiki/summaries/ares-core-review-2026-05-19.md` (§3, §5.5)
- Modern Fheya app: `Fheyalabs/ARES.git` `apps/fheya/`, currently
  worktree at `/Users/hardik/Fheya/worktrees/ares-impl/ARES/`
- ARES-core public release: <https://github.com/Fheyalabs/ARES-core/releases/tag/v0.3.1>

## Created

2026-05-19 (post v0.3.1).
