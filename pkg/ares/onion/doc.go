// SPDX-License-Identifier: Apache-2.0

// Package onion implements the client-side cryptography for ARES
// slot anonymization: X25519 ECIES envelopes, the SC-2-correct
// onion construction (N-1 layers including a self-layer, identified
// on peel by ciphertext memory match), and a deterministic slot
// permutation. It is transport- and application-agnostic; the
// framework's gossip phases drive it, and any participant client can
// reuse it directly.
package onion
