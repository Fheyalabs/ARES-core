//go:build openfhe

// SPDX-License-Identifier: Apache-2.0

package encrypted_input_ranking

import (
	"reflect"
	"testing"
)

func TestBuildEncryptedInputFuseRequestUsesCiphertextOnlyModes(t *testing.T) {
	request := CiphertextOnlyRequest{
		InitiatorProfileCiphertext: []byte("initiator-profile"),
		CandidateProfileCiphertexts: [][]byte{
			[]byte("candidate-0-profile"),
			[]byte("candidate-1-profile"),
		},
		CandidateDistanceCiphertexts: [][]byte{
			[]byte("candidate-0-distance"),
			[]byte("candidate-1-distance"),
		},
		CandidatePayloadCiphertexts: [][][]byte{
			{[]byte("candidate-0-payload-chunk-0")},
			{[]byte("candidate-1-payload-chunk-0")},
		},
		CandidateScoreOffsets: []int{2, -1},
		EvaluationMaterial: EvaluationMaterial{
			EvalMultFinal: []byte("eval-mult-final"),
			EvalSumFinal:  []byte("eval-sum-final"),
		},
		ProfileDimension: 8,
		PayloadSlotCount: 8,
		Comparators: []Comparator{{
			ID:         "wide-logistic",
			Kind:       "logistic",
			Gain:       3,
			Bound:      6,
			InputScale: 1,
			Degree:     13,
		}},
	}

	got, err := buildEncryptedInputFuseRequest(request)
	if err != nil {
		t.Fatalf("buildEncryptedInputFuseRequest() error = %v", err)
	}
	if len(got.InitiatorCiphertext) == 0 || len(got.CandidateCiphertexts) != 2 {
		t.Fatalf("profile ciphertexts were not mapped: %+v", got)
	}
	if len(got.CandidateDistanceCiphertexts) != 2 || len(got.CandidatePayloadCiphertexts) != 2 {
		t.Fatalf("encrypted distance/payload fields were not mapped: %+v", got)
	}
	requestType := reflect.TypeOf(got)
	for _, forbidden := range []string{"CandidatePackages", "CandidateLatQ", "CandidateLonQ", "InitiatorLatQ", "InitiatorLonQ"} {
		if _, present := requestType.FieldByName(forbidden); present {
			t.Fatalf("encrypted input request exposes forbidden plaintext field %q", forbidden)
		}
	}
	if got.CandidateBrownies[0] != 2 || got.CandidateBrownies[1] != -1 {
		t.Fatalf("public score offsets = %v, want [2 -1]", got.CandidateBrownies)
	}
}
