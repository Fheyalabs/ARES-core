# ARES Core

A cryptographic framework for blind ranking, sealed-bid auctions, and selective-reveal protocols. Compose N-party cryptographic sessions from pluggable units called **phases**.

## Quickstart

```go
import auction "github.com/Fheyalabs/ares-core/examples/sealed_bid_auction"

runner, err := auction.Pipeline()
ctx, err := runner.BeginSession("auction-1", "")
// Route messages through runner.HandleMessage(...)
```

ARES-core ships generic phase primitives (`pkg/ares/phase/defaults`,
`pkg/ares/phase/keygen`); applications compose their own pipeline via
`phase.Compose(...)`. The framework intentionally provides no
opinionated "default runner" — see `examples/` for full pipelines.

## Documentation

See `pkg/ares/phase/README.md` for the full framework guide — concepts, quickstart, core catalog, customizing recipes, and reference-apps table.

## Reference Apps

| App | Path | Description |
|---|---|---|
| Sealed-bid auction | `examples/sealed_bid_auction/` | 6-phase scalar-bid argmax pipeline, depth=10 |
| Recurring cohort ranking | `examples/recurring_cohort_ranking/` | 10-phase amortized-keygen pipeline across two runners |

## Related Repos

- **ARES (Fheya app)** — `github.com/Fheyalabs/ARES` — the Fheya matchmaking application built on ARES Core.

## License

To be determined.
