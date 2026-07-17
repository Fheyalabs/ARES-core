// SPDX-License-Identifier: Apache-2.0

package encrypted_input_ranking

import (
	"reflect"
	"testing"
)

func TestCiphertextOnlyRequestValidatesEncryptedCandidateInputs(t *testing.T) {
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
		CandidateScoreOffsets: []int{0, 0},
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

	if err := request.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestCiphertextOnlyRequestRejectsMismatchedEncryptedCandidates(t *testing.T) {
	request := CiphertextOnlyRequest{
		InitiatorProfileCiphertext: []byte("initiator-profile"),
		CandidateProfileCiphertexts: [][]byte{
			[]byte("candidate-0-profile"),
		},
		CandidateDistanceCiphertexts: [][]byte{
			[]byte("candidate-0-distance"),
			[]byte("candidate-1-distance"),
		},
		CandidatePayloadCiphertexts: [][][]byte{
			{[]byte("candidate-0-payload-chunk-0")},
		},
		CandidateScoreOffsets: []int{0},
		EvaluationMaterial:    EvaluationMaterial{EvalMultFinal: []byte("mult"), EvalSumFinal: []byte("sum")},
		ProfileDimension:      8,
		PayloadSlotCount:      8,
		Comparators:           []Comparator{{ID: "lane", Kind: "logistic", Gain: 3, Bound: 6, InputScale: 1, Degree: 13}},
	}

	if err := request.Validate(); err == nil {
		t.Fatal("Validate() accepted a mismatched encrypted distance set")
	}
}

func TestCiphertextOnlyRequestAllowsOmittedPublicScoreOffsets(t *testing.T) {
	request := CiphertextOnlyRequest{
		InitiatorProfileCiphertext: []byte("initiator-profile"),
		CandidateProfileCiphertexts: [][]byte{
			[]byte("candidate-0-profile"),
		},
		CandidateDistanceCiphertexts: [][]byte{
			[]byte("candidate-0-distance"),
		},
		CandidatePayloadCiphertexts: [][][]byte{
			{[]byte("candidate-0-payload-chunk-0")},
		},
		EvaluationMaterial: EvaluationMaterial{EvalMultFinal: []byte("mult"), EvalSumFinal: []byte("sum")},
		ProfileDimension:   8,
		PayloadSlotCount:   8,
		Comparators:        []Comparator{{ID: "lane", Kind: "logistic", Gain: 3, Bound: 6, InputScale: 1, Degree: 13}},
	}

	if err := request.Validate(); err != nil {
		t.Fatalf("Validate() with no score offsets error = %v", err)
	}
	if got := request.scoreOffsets(); !reflect.DeepEqual(got, []int{0}) {
		t.Fatalf("scoreOffsets() = %v, want [0]", got)
	}
}

func TestCiphertextOnlyRequestHasNoPlaintextPayloadOrLocationFields(t *testing.T) {
	typ := reflect.TypeOf(CiphertextOnlyRequest{})
	for _, forbidden := range []string{
		"CandidatePackages",
		"CandidateLatQ",
		"CandidateLonQ",
		"InitiatorLatQ",
		"InitiatorLonQ",
	} {
		if _, found := typ.FieldByName(forbidden); found {
			t.Fatalf("CiphertextOnlyRequest exposes forbidden plaintext field %q", forbidden)
		}
	}
}
