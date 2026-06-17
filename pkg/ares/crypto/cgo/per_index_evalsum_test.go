// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"math"
	"testing"
)

func TestPerIndexEvalKeyRound1SupportsDotProduct(t *testing.T) {
	params := ContractParams{
		RingDim:             1024,
		ScalingFactor:       float64(uint64(1) << 50),
		Depth:               2,
		MinimalRotationKeys: true,
		ProfileDim:          4,
		PayloadSlotCount:    8,
	}
	ctx, err := NewCryptoContext(params)
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	defer ctx.Close()

	shares := make([]DistributedKeyShare, 3)
	shares[0], err = DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	for i := 1; i < len(shares); i++ {
		shares[i], err = DistributedKeyGenNext(params, shares[i-1].PublicKey)
		if err != nil {
			t.Fatalf("keygen next %d: %v", i, err)
		}
	}

	perIndex := make([][]IndexedEvalSumKey, len(shares))
	perIndex[0], err = GeneratePerIndexEvalSumKeysWithContext(ctx, shares[0].SecretKeyShare)
	if err != nil {
		t.Fatalf("per-index lead: %v", err)
	}
	for i := 1; i < len(shares); i++ {
		perIndex[i], err = GeneratePerIndexEvalSumSharesWithContext(ctx, shares[i].SecretKeyShare, perIndex[0], shares[i].PublicKey)
		if err != nil {
			t.Fatalf("per-index participant %d: %v", i, err)
		}
	}

	lead, err := EvalKeyRound1LeadWithContext(ctx, shares[0].SecretKeyShare)
	if err != nil {
		t.Fatalf("merged round1 lead: %v", err)
	}
	publicKeys := make([][]byte, len(shares))
	multRound1 := make([][]byte, len(shares))
	publicKeys[0] = shares[0].PublicKey
	multRound1[0] = lead.EvalMultBase
	for i := 1; i < len(shares); i++ {
		publicKeys[i] = shares[i].PublicKey
		r1, err := EvalKeyRound1ParticipantWithContext(ctx, shares[i].SecretKeyShare, lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			t.Fatalf("merged round1 participant %d: %v", i, err)
		}
		multRound1[i] = r1.EvalMultSwitchShare
	}

	indexed, err := CombineEvalKeyRound1PerIndexWithContext(ctx, publicKeys, multRound1, perIndex)
	if err != nil {
		t.Fatalf("per-index combine: %v", err)
	}

	finalPK := shares[len(shares)-1].PublicKey
	finalShares := make([][]byte, len(shares))
	for i := range shares {
		r2, err := EvalKeyRound2ParticipantWithContext(ctx, shares[i].SecretKeyShare, indexed.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			t.Fatalf("round2 participant %d: %v", i, err)
		}
		finalShares[i] = r2.EvalMultFinalShare
	}
	final, err := CombineEvalKeyRound2WithContext(ctx, finalPK, finalShares, indexed.EvalSumFinal)
	if err != nil {
		t.Fatalf("combine round2: %v", err)
	}

	left := []float64{1, 2, 3, 4}
	right := []float64{0.5, -1, 0.25, 2}
	leftCT, err := EncryptCKKSForContract(params, finalPK, left)
	if err != nil {
		t.Fatalf("encrypt left: %v", err)
	}
	rightCT, err := EncryptCKKSForContract(params, finalPK, right)
	if err != nil {
		t.Fatalf("encrypt right: %v", err)
	}
	dotCT, err := EvalProductSumForContract(params, final, leftCT, rightCT, len(left))
	if err != nil {
		t.Fatalf("eval product sum: %v", err)
	}
	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, dotCT, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	got, err := FuseCKKSPartialsForContract(params, partials, 1)
	if err != nil {
		t.Fatalf("fuse dot partials: %v", err)
	}
	want := 0.0
	for i := range left {
		want += left[i] * right[i]
	}
	if math.Abs(got[0]-want) > 0.05 {
		t.Fatalf("dot product = %.6f, want %.6f", got[0], want)
	}
}

func TestPerIndexEvalSumValidationRejectsMismatchedIndices(t *testing.T) {
	_, _, err := validateIndexedEvalSumShares([][]IndexedEvalSumKey{
		{{Index: 1, Key: []byte("lead-1")}, {Index: 2, Key: []byte("lead-2")}},
		{{Index: 1, Key: []byte("share-1")}},
	})
	if err == nil {
		t.Fatal("expected mismatched index validation error")
	}
}
