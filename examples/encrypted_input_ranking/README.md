<!-- SPDX-License-Identifier: Apache-2.0 -->

# Ciphertext-only CKKS ranking

This reference flow ranks encrypted candidate inputs with threshold CKKS. It is
framework-generic: it does not assume a particular product, identity system, or
payload format.

## Privacy boundary

The caller submits only:

- one encrypted profile vector for the initiator and each candidate;
- one client-derived encrypted squared-distance ciphertext per candidate;
- a candidate-major, chunk-major matrix of encrypted payload ciphertexts;
- collective public evaluation material; and
- optional public policy score offsets.

`CiphertextOnlyRequest` deliberately exposes **no plaintext payload or location
fields**. The OpenFHE adapter maps its encrypted inputs to
`cgo.EncryptedInputFuseRequest.CandidatePayloadCiphertexts` and
`cgo.EncryptedInputFuseRequest.CandidateDistanceCiphertexts`. The target type
has no package or coordinate fields, so a caller cannot represent a mixed
plaintext/ciphertext request. Decryption shares remain a separate threshold
protocol step.

The client derives each distance ciphertext locally from encrypted origin
material and its local coordinates. The evaluator receives the result
ciphertext, not source coordinates. Payload chunks are encrypted by their
owners before submission; the evaluator never receives package bytes.

## Usage

Build a request from already-encrypted inputs, then score it with a
production-calibrated CKKS parameter set and one or more approximation lanes:

```go
request := encrypted_input_ranking.CiphertextOnlyRequest{
    InitiatorProfileCiphertext: initiatorProfileCiphertext,
    CandidateProfileCiphertexts: candidateProfileCiphertexts,
    CandidateDistanceCiphertexts: candidateDistanceCiphertexts,
    CandidatePayloadCiphertexts: candidatePayloadCiphertexts,
    CandidateScoreOffsets: policyOffsets,
    EvaluationMaterial: encrypted_input_ranking.EvaluationMaterial{
        EvalMultFinal: evalMultFinal,
        EvalSumFinal: evalSumFinal,
    },
    ProfileDimension: profileDimension,
    PayloadSlotCount: payloadSlotCount,
    Alpha: alpha,
    Beta: beta,
    Gamma: gamma,
    Comparators: []encrypted_input_ranking.Comparator{
        {ID: "wide-logistic", Kind: "logistic", Gain: 3, Bound: 6, InputScale: 1, Degree: 13},
        {ID: "narrow-tanh", Kind: "tanh_chebyshev", Gain: 4, Bound: 3, InputScale: 0.5, Degree: 13},
    },
}

lanes, err := encrypted_input_ranking.Score(contractParams, request)
if err != nil {
    // Reject the session or retry according to the caller's protocol policy.
}
// lanes[lane][chunk] is the encrypted winner payload output for that lane.
```

`Score` calls `cgo.ChunkedUnionScoreEncryptedInputsCKKS`, which builds one
CKKS context and reuses it across lanes. It intentionally uses serial lane
execution. Native comparator concurrency is opt-in elsewhere and must be
measured against the deployment's memory budget.

## Tests

The default test checks request construction and ciphertext-only mode
separation without OpenFHE:

```bash
go test ./examples/encrypted_input_ranking
```

The build-tagged smoke test checks the real `EncryptedInputFuseRequest` mapping without
performing key generation or homomorphic evaluation:

```bash
GOMAXPROCS=1 go test -p 1 -tags openfhe ./examples/encrypted_input_ranking
```

It is not a cryptographic correctness or resource certification. Run a
separate, serial, deployment-shaped threshold CKKS integration test before
using a new parameter profile in production.
