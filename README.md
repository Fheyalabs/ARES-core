# ARES Core

[![go](https://github.com/Fheyalabs/ARES-core/actions/workflows/go.yml/badge.svg)](https://github.com/Fheyalabs/ARES-core/actions/workflows/go.yml)
[![openfhe](https://github.com/Fheyalabs/ARES-core/actions/workflows/openfhe.yml/badge.svg)](https://github.com/Fheyalabs/ARES-core/actions/workflows/openfhe.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

ARES Core is a cryptographic framework for **blind ranking**,
**sealed-bid auctions**, and **selective-reveal protocols**. It composes
N-party cryptographic sessions from pluggable units called **phases**:

- Threshold CKKS keygen, FHE scoring, and threshold decrypt — out of the box.
- Pluggable input shapes, scoring circuits, and post-result phases.
- Pluggable trust models — multi-party threshold, single-party trusted,
  plaintext (for testing), or pre-shared / amortized keygen.

The framework intentionally ships **no opinionated default pipeline**.
Applications compose their own via `phase.Compose(...)` from generic
primitives in `pkg/ares/phase/defaults/` and `pkg/ares/phase/keygen/`,
plus their own input-submission / scoring / post-result phases.

> Status: pre-1.0. Minor version bumps may include breaking API
> changes. See [CHANGELOG.md](CHANGELOG.md) for the migration path.

## Reference apps

Four worked examples ship under `examples/`:

| App | Path | Pipeline | Depth |
|---|---|---|---|
| Sealed-bid auction | [`examples/sealed_bid_auction/`](examples/sealed_bid_auction/) | 6 phases — scalar bid + argmax | 10 |
| Ride share | [`examples/ride_share/`](examples/ride_share/) | 6 phases — composite score (price × proximity) | 12 |
| Recurring cohort ranking | [`examples/recurring_cohort_ranking/`](examples/recurring_cohort_ranking/) | 10 phases across 2 runners — amortized keygen | 10 |
| Blind voting | [`examples/voting/`](examples/voting/) | 5 phases — `PlaintextKeygen` + sum-weighted tally | n/a |

The dating-app reference implementation built on this framework lives
at [fheya.de](https://fheya.de) — it's not open-source, but exists as
proof the framework supports the most complex shape it's designed for
(cosine + location + reputation scoring across 6 parties at depth 30).

## Quickstart

```go
import auction "github.com/Fheyalabs/ARES-core/examples/sealed_bid_auction"

runner, err := auction.Pipeline()
ctx, err := runner.BeginSession("auction-1", "")
// Route messages through runner.HandleMessage(...)
```

For a hand-composed pipeline see
[`pkg/ares/phase/README.md`](pkg/ares/phase/README.md).

## Build your own app in <100 LOC

A complete worked example: an anonymous "highest-rating" picker that
runs without any FHE. Each participant submits an integer rating; the
server tallies them and writes the winner to session context.

Three phases — two provided by the framework, one you write.

```go
// myapp/states.go (16 lines)
package myapp

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"
import "github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"

const (
	StateDone phase.SessionState = "DONE"

	CtxRatings = "myapp.ratings" // map[string]int
	CtxWinner  = "myapp.winner"  // string
)

// CtxParticipants is the framework-supplied participant list, written
// by defaults.Phase1aSessionInitiation. Re-exported for readability.
const CtxParticipants = defaults.CtxParticipants
```

```go
// myapp/phases.go (~55 lines)
package myapp

import (
	"encoding/json"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// PhaseTally is the only app-specific phase. It accumulates one
// "myapp.rating" frame per participant, picks the highest, and writes
// the winner pseudonym to the session context. The framework's
// Phase1a (invitation) and PlaintextKeygen (no-op crypto) sit in
// front of it so participants are bootstrapped before this phase runs.
type PhaseTally struct{}

func (PhaseTally) Name() string                         { return "myapp-tally" }
func (PhaseTally) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (PhaseTally) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (PhaseTally) EntryState() phase.SessionState       { return defaults.StateGossip }
func (PhaseTally) ExitState() phase.SessionState        { return StateDone }
func (PhaseTally) ConsumedMessageTypes() []string       { return []string{"myapp.rating"} }
func (PhaseTally) InternalStates() []phase.SessionState { return nil }
func (PhaseTally) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxParticipants: {TypeName: "[]string", Required: true}}
}
func (PhaseTally) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxRatings: {TypeName: "map[string]int"}, CtxWinner: {TypeName: "string"}}
}
func (PhaseTally) Enter(*phase.SessionContext) error { return nil }
func (PhaseTally) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, "ratings", from, payload)
	return nil
}
func (PhaseTally) CheckComplete(ctx *phase.SessionContext) bool {
	return phase.QuorumReached(ctx, "ratings", len(phase.MustGet[[]string](ctx, CtxParticipants)))
}
func (PhaseTally) Exit(ctx *phase.SessionContext) error {
	raw, winner, best := phase.AccumulatedMessages(ctx, "ratings"), "", -1<<31
	totals := make(map[string]int, len(raw))
	for who, p := range raw {
		var m struct{ Value int `json:"value"` }
		_ = json.Unmarshal(p, &m)
		totals[who] = m.Value
		if m.Value > best {
			winner, best = who, m.Value
		}
	}
	ctx.Set(CtxRatings, totals)
	ctx.Set(CtxWinner, winner)
	return nil
}
```

```go
// myapp/runner.go (15 lines)
package myapp

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/keygen"
)

func Pipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		defaults.NewPhase1aSessionInitiation(), // INVITING -> LOCKED
		keygen.NewPlaintextKeygen(),            // LOCKED   -> GOSSIP (no FHE)
		PhaseTally{},                           // GOSSIP   -> DONE
	)
}
```

That's it — under 90 lines of source. Compose with `phase.Compose`,
point a `transport.Service` at the runner, and you have a working app
that handles invitations, participant bootstrap, message accumulation
with quorum, deterministic state machine validation, and audit logging
for free.

To swap in real FHE later, replace `keygen.NewPlaintextKeygen()` with
`defaults.NewPhase0aThresholdKeygen()` and add a
`defaults.NewPhase3ThresholdDecrypt()` step before the tally — the
framework's composition guard catches the topology mismatch at
construction time if you mix them up.

The four reference apps under `examples/` are larger only because they
add real CKKS, signed transcripts, multiple runners, or amortized
keygen — none of which is required to *start*. See
[`examples/voting/`](examples/voting/) for the closest match to this
shape with tests.

## Install

### Go dependency

```bash
go get github.com/Fheyalabs/ARES-core@latest
```

### OpenFHE prerequisite

ARES Core links the **OpenFHE 1.5.x** C++ library for its CKKS
primitives. Pin to 1.5.1 — earlier versions choose different cyclotomic
primes for the same nominal parameters and ciphertexts won't
interoperate across versions (the framework detects this and refuses to
proceed).

```bash
git clone --branch v1.5.1 --depth 1 https://github.com/openfheorg/openfhe-development.git
cd openfhe-development
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)        # or `sysctl -n hw.ncpu` on macOS
sudo make install
```

ARES Core's cgo paths search `/usr/local`, `/opt/homebrew`, and
`/usr/local/lib64` by default. For other prefixes, override via
`CGO_CXXFLAGS` / `CGO_LDFLAGS` — see
[`pkg/ares/crypto/cgo/bridge.go`](pkg/ares/crypto/cgo/bridge.go) for the
exact override pattern, and `pkg-config/openfhe.pc.in` for a
pkg-config template.

### Build the helper binary

```bash
git clone https://github.com/Fheyalabs/ARES-core.git
cd ARES-core
go build -tags openfhe -o bin/openfhe-helper ./cmd/openfhe-contract-helper
./bin/openfhe-helper --version    # should print v1.5.1
```

### Run tests

```bash
go test ./...                       # Go-only tests; no OpenFHE needed
go test -tags openfhe ./...         # full suite; requires OpenFHE
```

## Documentation

- [Framework concepts and customizing recipes](pkg/ares/phase/README.md)
- [Reference apps overview](#reference-apps) above
- [Python smoke scripts](clients/python/examples/README.md)
- [Deployment recipes for homelab](deploy/README.md)
- [CHANGELOG.md](CHANGELOG.md)

## Contributing

Pull requests welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: please follow [SECURITY.md](SECURITY.md) rather than
filing public issues.

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
