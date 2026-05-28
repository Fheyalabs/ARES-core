<!-- SPDX-License-Identifier: Apache-2.0 -->

# Recurring cohort ranking

Reference app: a cohort of fixed members runs a weekly
encrypted-ranking session, with the expensive
threshold-CKKS keygen amortized once at cohort formation and
reused across weekly sessions. Two distinct runners share state
through a `lineage.Store`.

## What it demonstrates

- Per-cohort key bundle reuse — `FormationPipeline` produces
  threshold-CKKS keys once; `WeeklyPipeline` runs many sessions
  reusing them via pre-shared keys.
- A non-trivial 10-phase composition spread across two runners
  with shared session state.
- v0.4.0 SC-10 lineage spanning the two runners: weekly-ranking
  commits can resolve parent refs back to the formation
  commits when both runners write to the same `lineage.Store`.

## Pipelines

```text
FormationPipeline:
  FormCohort → ThresholdKeygen → COHORT_SEALED (terminal)

WeeklyPipeline:
  Invite → PreSharedKeyLookup → SubmitRating → Argmax → Decrypt → Settle
```

## Usage

Legacy (no lineage):

```go
formation, _ := cohort.FormationPipeline()
formation, _  = cohort.FormationPipelineWithHelper(helperClient)

weekly, _    := cohort.WeeklyPipeline()
weekly, _     = cohort.WeeklyPipelineWithHelper(helperClient, sharpening)
```

v0.4.0 lineage variant — both runners share one Store:

```go
store     := lineage.NewInMemoryStore()
signer, _ := sign.NewEd25519Signer()
verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

formation, _ := cohort.FormationPipelineWithLineage(store, signer, verifiers)
weekly, _    := cohort.WeeklyPipelineWithLineage(store, signer, verifiers)
```

For helper-backed real CKKS (helper is the first positional arg in
both constructors — passed in before the shared store):

```go
formation, _ := cohort.FormationPipelineWithLineageAndHelper(helper, store, signer, verifiers)
weekly, _    := cohort.WeeklyPipelineWithLineageAndHelper(helper, sharpening, store, signer, verifiers)
```

The shared `store` is what makes cross-runner lineage work — a
weekly-ranking commit's parent refs resolve back to cohort-keygen
commits, producing a unified per-cohort Merkle DAG.

## Tamper-detection smoke

[`tamper_test.go`](tamper_test.go) — two tests over
`FormationPipelineWithLineage`:
- `TamperedKeygenShare_DetectedByLineage` — a member's signed
  keygen share is rebodied with attacker bytes; the runner
  rejects it with `*lineage.MismatchError{Field:"PayloadHash"}`.
- `LineageStoreIsShareable` — confirms two runners can be built
  over the same `lineage.Store`, enabling cross-runner DAG
  resolution between formation and weekly sessions.

## Running as a service

[`cmd/session-service`](cmd/session-service) — single binary that
serves both runners through one HTTP+WebSocket service; the
admin endpoint chooses formation vs weekly per request. The
service binary currently uses the legacy `FormationPipeline()` /
`WeeklyPipeline()` constructors.

## References

- ARES Spec v2.5 §SC-10.
- [`pkg/ares/lineage/`](../../pkg/ares/lineage/),
  [`pkg/ares/sign/`](../../pkg/ares/sign/).
- [CHANGELOG `[0.4.0]`](../../CHANGELOG.md).
