//go:build openfhe

// SPDX-License-Identifier: Apache-2.0

package encrypted_input_ranking

import cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"

// Score runs a ciphertext-only CKKS union ranking. It constructs one native
// context and reuses it across comparator lanes. The default helper is serial;
// callers should measure memory before opting into native comparator fanout.
func Score(params cgo.ContractParams, request CiphertextOnlyRequest) ([][][]byte, error) {
	fuseRequest, err := buildFullFuseRequest(request)
	if err != nil {
		return nil, err
	}
	comparators := buildComparators(request.Comparators)
	return cgo.ChunkedUnionScoreEncryptedInputsCKKS(params, fuseRequest, comparators)
}

func buildFullFuseRequest(request CiphertextOnlyRequest) (cgo.FullFuseRequest, error) {
	if err := request.Validate(); err != nil {
		return cgo.FullFuseRequest{}, err
	}
	return cgo.FullFuseRequest{
		InitiatorCiphertext:          request.InitiatorProfileCiphertext,
		CandidateCiphertexts:         request.CandidateProfileCiphertexts,
		CandidateDistanceCiphertexts: request.CandidateDistanceCiphertexts,
		CandidatePayloadCiphertexts:  request.CandidatePayloadCiphertexts,
		CandidateBrownies:            request.scoreOffsets(),
		ProfileDim:                   request.ProfileDimension,
		PayloadSlotCount:             request.PayloadSlotCount,
		Alpha:                        request.Alpha,
		Beta:                         request.Beta,
		Gamma:                        request.Gamma,
		EvalKeys: cgo.EvalKeyFinal{
			EvalMultFinal: request.EvaluationMaterial.EvalMultFinal,
			EvalSumFinal:  request.EvaluationMaterial.EvalSumFinal,
		},
	}, nil
}

func buildComparators(comparators []Comparator) []cgo.UnionComparator {
	built := make([]cgo.UnionComparator, len(comparators))
	for index, comparator := range comparators {
		built[index] = cgo.UnionComparator{
			ID:         comparator.ID,
			Comparator: comparator.Kind,
			Schedule:   comparator.Schedule,
			Gain:       comparator.Gain,
			Bound:      comparator.Bound,
			InputScale: comparator.InputScale,
			Degree:     comparator.Degree,
		}
	}
	return built
}
