// SPDX-License-Identifier: Apache-2.0

// Package encrypted_input_ranking demonstrates ciphertext-only CKKS ranking.
// It is deliberately domain-neutral: callers provide already-encrypted profile,
// distance, and payload inputs, then select their own public scoring policy.
package encrypted_input_ranking

import "fmt"

// EvaluationMaterial holds public collective evaluation keys. It does not hold
// decryption material.
type EvaluationMaterial struct {
	EvalMultFinal []byte
	EvalSumFinal  []byte
}

// Comparator defines one independent approximation lane in a union score.
// Several lanes improve recovery robustness without changing the score inputs.
type Comparator struct {
	ID         string
	Kind       string
	Schedule   string
	Gain       float64
	Bound      float64
	InputScale float64
	Degree     int
}

// CiphertextOnlyRequest contains every input required for an encrypted-input
// ranking. It intentionally has no raw payload or coordinate fields.
//
// CandidateProfileCiphertexts, CandidateDistanceCiphertexts, and
// CandidatePayloadCiphertexts are candidate-major. Each payload entry is a
// chunk-major ciphertext matrix. CandidateScoreOffsets are explicitly public
// policy inputs; omit them or use zeroes when no public offset applies.
type CiphertextOnlyRequest struct {
	InitiatorProfileCiphertext   []byte
	CandidateProfileCiphertexts  [][]byte
	CandidateDistanceCiphertexts [][]byte
	CandidatePayloadCiphertexts  [][][]byte
	CandidateScoreOffsets        []int
	EvaluationMaterial           EvaluationMaterial
	ProfileDimension             int
	PayloadSlotCount             int
	Alpha                        float64
	Beta                         float64
	Gamma                        float64
	Comparators                  []Comparator
}

// Validate checks the ciphertext-only request shape before any native context
// is allocated.
func (r CiphertextOnlyRequest) Validate() error {
	if len(r.InitiatorProfileCiphertext) == 0 {
		return fmt.Errorf("initiator profile ciphertext is required")
	}
	n := len(r.CandidateProfileCiphertexts)
	if n == 0 {
		return fmt.Errorf("at least one candidate profile ciphertext is required")
	}
	if len(r.CandidateDistanceCiphertexts) != n {
		return fmt.Errorf("candidate distance ciphertext count = %d, want %d", len(r.CandidateDistanceCiphertexts), n)
	}
	if len(r.CandidatePayloadCiphertexts) != n {
		return fmt.Errorf("candidate payload ciphertext count = %d, want %d", len(r.CandidatePayloadCiphertexts), n)
	}
	if len(r.CandidateScoreOffsets) != 0 && len(r.CandidateScoreOffsets) != n {
		return fmt.Errorf("candidate score offset count = %d, want %d", len(r.CandidateScoreOffsets), n)
	}
	if r.ProfileDimension <= 0 || r.PayloadSlotCount <= 0 {
		return fmt.Errorf("profile dimension and payload slot count must be positive")
	}
	if len(r.EvaluationMaterial.EvalMultFinal) == 0 || len(r.EvaluationMaterial.EvalSumFinal) == 0 {
		return fmt.Errorf("final evaluation material is required")
	}
	if len(r.Comparators) == 0 {
		return fmt.Errorf("at least one comparator is required")
	}

	expectedChunks := (r.PayloadSlotCount + nextPowerOfTwo(r.ProfileDimension) - 1) / nextPowerOfTwo(r.ProfileDimension)
	for candidate := 0; candidate < n; candidate++ {
		if len(r.CandidateProfileCiphertexts[candidate]) == 0 {
			return fmt.Errorf("candidate profile ciphertext %d is empty", candidate)
		}
		if len(r.CandidateDistanceCiphertexts[candidate]) == 0 {
			return fmt.Errorf("candidate distance ciphertext %d is empty", candidate)
		}
		if len(r.CandidatePayloadCiphertexts[candidate]) != expectedChunks {
			return fmt.Errorf("candidate payload ciphertext %d has %d chunks, want %d", candidate, len(r.CandidatePayloadCiphertexts[candidate]), expectedChunks)
		}
		for chunk, ciphertext := range r.CandidatePayloadCiphertexts[candidate] {
			if len(ciphertext) == 0 {
				return fmt.Errorf("candidate payload ciphertext %d chunk %d is empty", candidate, chunk)
			}
		}
	}
	for lane, comparator := range r.Comparators {
		if comparator.ID == "" || comparator.Kind == "" {
			return fmt.Errorf("comparator %d must have an ID and kind", lane)
		}
		if comparator.Bound <= 0 || comparator.InputScale <= 0 || comparator.Degree <= 0 {
			return fmt.Errorf("comparator %q must have positive bound, input scale, and degree", comparator.ID)
		}
	}
	return nil
}

func (r CiphertextOnlyRequest) scoreOffsets() []int {
	if len(r.CandidateScoreOffsets) != 0 {
		return r.CandidateScoreOffsets
	}
	return make([]int, len(r.CandidateProfileCiphertexts))
}

func nextPowerOfTwo(value int) int {
	power := 1
	for power < value {
		power <<= 1
	}
	return power
}
