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
