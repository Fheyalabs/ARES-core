# AresClient (Swift)

Swift client library for the [ARES-core](https://github.com/Fheyalabs/ARES-core) protocol's
wire-layer crypto primitives. Implements the SC-2 onion shuffle, SC-10 ciphertext-lineage
`DAGNode`, the v2 `WSMessage` frame, and device-key signing — all in pure Swift on top of
[apple/swift-crypto](https://github.com/apple/swift-crypto) (CryptoKit-compatible; runs on
macOS and Linux). Validated byte-for-byte against the cross-language golden vectors shared
with the Go and Python clients.

## Status / scope

This is **L1** — protocol-crypto primitives only. The following are explicitly out of scope
at this layer and are planned for later work:

| Layer | Contents |
|---|---|
| L2 | FHE client operations (threshold CKKS key generation, ciphertext submission) |
| L3 | WS transport, session lifecycle, orchestration |

## Layout

```
Sources/AresClient/
  ByteUtil.swift      — hex encoding, constant-time bytes helpers
  Lineage.swift       — SC-10 DAGNode: build slot nodes, serialize v2 wire JSON
  Onion.swift         — SC-2 onion-encrypt and batch-peel
  Signing.swift       — canonical-JSON serialisation + Ed25519 device-key signing
  WireFrame.swift     — JSONValue / RawJSON types; WSMessage v2 frame codec

Tests/AresClientTests/
  ByteUtilTests.swift
  LineageVectorsTests.swift  — golden-vector parity with Go/Python (loads node_vectors.json)
  OnionTests.swift
  SigningTests.swift
  WireFrameTests.swift
  GoldenVectorLoader.swift   — shared fixture loader
```

## Requirements

- Swift 5.9+
- macOS 13+ or any Linux distribution with Swift toolchain

## Usage

Add to `Package.swift`:

```swift
.package(url: "https://github.com/Fheyalabs/ARES-core", from: "0.5.0")
// then in your target:
.product(name: "AresClient", package: "ARES-core")
```

### Build a lineage node for a slot submission

```swift
import AresClient

let (node, sk, pk) = try Lineage.buildSlotNode(
    sessionID: "session-abc123",
    payloadBytes: Data(repeating: 0xAB, count: 32),
    parentsHex: [],          // first node in chain — no parents
    phaseID: "anon-g-verify",
    role: "slot-submission"
)
// node.toWireJSON() produces the canonical v2 hex+snake_case JSON blob
print(node.id)              // hex node ID
print(pk.hexString)         // Ed25519 public key
```

### Build and peel an onion

```swift
import AresClient

// Peer public keys (Curve25519)
let peerPubs: [Data] = [pubKey0, pubKey1, pubKey2]

// Build onion — selfIndex identifies which layer wraps our own return path
let (onion, selfMemo) = try Onion.build(
    payload: Data("hello".utf8),
    peerPubs: peerPubs,
    selfIndex: 1
)

// Each relay calls peelBatch with its own secret key
let (peeled, ownIndex) = try Onion.peelBatch(
    mySk: mySecretKey,
    selfMemo: selfMemo,
    onions: [onion]
)
```

## Testing

Run all tests from the repo root (the package is tested in-tree):

```bash
cd clients/swift && swift test
```

The lineage golden-vector test (`LineageVectorsTests`) loads
`pkg/ares/lineage/testdata/node_vectors.json` from the repository via `#filePath`-relative
resolution — this is a repo-relative path and the single source of truth for cross-language
parity with the Go and Python clients.

### A note on Ed25519 signatures

`apple/swift-crypto`'s `Curve25519.Signing` uses a randomized Ed25519 implementation, so
signature bytes differ across runs. The signing tests therefore **verify** signatures against
the signer's public key rather than byte-comparing them to the golden vectors. This does not
affect interop: the ARES session service verifies signatures in the same way.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
