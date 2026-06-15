// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"math"
	"testing"
)

func TestDistributedKeygenCiphertextContractRoundTrip(t *testing.T) {
	params := DefaultContractParams(8, 4)
	first, err := DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("first keygen share: %v", err)
	}
	second, err := DistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("second keygen share: %v", err)
	}
	third, err := DistributedKeyGenNext(params, second.PublicKey)
	if err != nil {
		t.Fatalf("third keygen share: %v", err)
	}

	profile := []float64{1.0, 0.5, -0.25, 0.125}
	ct, err := EncryptCKKSForContract(params, third.PublicKey, profile)
	if err != nil {
		t.Fatalf("encrypt profile ciphertext: %v", err)
	}
	partials := make([][]byte, 0, 3)
	for _, share := range []DistributedKeyShare{first, second, third} {
		partial, err := PartialDecryptCKKSForContract(params, ct, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	got, err := FuseCKKSPartialsForContract(params, partials, len(profile))
	if err != nil {
		t.Fatalf("fuse partials: %v", err)
	}
	if len(got) != len(profile) {
		t.Fatalf("fused slots = %d, want %d", len(got), len(profile))
	}
	for i, want := range profile {
		if math.Abs(got[i]-want) > 0.01 {
			t.Fatalf("slot %d = %.6f, want %.6f (all slots=%v)", i, got[i], want, got)
		}
	}
}

func TestDistributedEvalKeysSupportCiphertextDotProduct(t *testing.T) {
	params := DefaultContractParams(8, 6)
	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)

	left := []float64{1.0, 2.0, 3.0, 4.0}
	right := []float64{0.5, -1.0, 0.25, 2.0}
	leftCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, left)
	if err != nil {
		t.Fatalf("encrypt left: %v", err)
	}
	rightCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, right)
	if err != nil {
		t.Fatalf("encrypt right: %v", err)
	}
	dotCT, err := EvalProductSumForContract(params, evalKeys, leftCT, rightCT, len(left))
	if err != nil {
		t.Fatalf("evaluate encrypted dot product: %v", err)
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
		t.Fatalf("dot = %.6f, want %.6f", got[0], want)
	}
}

func TestFullFusePayloadUsesSubmittedCiphertexts(t *testing.T) {
	params := DefaultContractParams(32, 12)
	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)

	initProfile := []float64{1, 0, 0, 0}
	loserProfile := []float64{0, 1, 0, 0}
	winnerProfile := []float64{1, 0, 0, 0}
	initCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, initProfile)
	if err != nil {
		t.Fatalf("encrypt initiator profile: %v", err)
	}
	loserCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, loserProfile)
	if err != nil {
		t.Fatalf("encrypt loser profile: %v", err)
	}
	winnerCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, winnerProfile)
	if err != nil {
		t.Fatalf("encrypt winner profile: %v", err)
	}

	loserPackage := []int{0x11, 0x22, 0x33, 0x44}
	winnerPackage := []int{0xA5, 0x5A, 0xC3, 0x3C}
	ctWinner, err := FullFusePayloadCKKS(params, FullFuseRequest{
		InitiatorCiphertext:  initCT,
		InitiatorLatQ:        0,
		InitiatorLonQ:        0,
		CandidateCiphertexts: [][]byte{loserCT, winnerCT},
		CandidateLatQ:        []int{0, 0},
		CandidateLonQ:        []int{0, 0},
		CandidateBrownies:    []int{0, 0},
		CandidatePackages:    [][]int{loserPackage, winnerPackage},
		ProfileDim:           len(initProfile),
		Alpha:                0,
		Beta:                 1,
		Gamma:                0,
		Comparator:           "tanh_chebyshev",
		ComparatorDegree:     7,
		ComparatorGain:       40,
		ComparatorScale:      1,
		ComparatorBound:      1,
		SelectorSchedule:     "none",
		EvalKeys:             evalKeys,
		PackageBytes:         len(winnerPackage),
		PayloadSlotCount:     len(winnerPackage) * 8,
	})
	if err != nil {
		t.Fatalf("full fuse payload: %v", err)
	}
	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, ctWinner, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	slots, err := FuseCKKSPartialsForContract(params, partials, len(winnerPackage)*8)
	if err != nil {
		t.Fatalf("fuse full payload partials: %v", err)
	}
	recovered := slotsToBytesForTest(slots, len(winnerPackage))
	for i, want := range winnerPackage {
		if recovered[i] != byte(want) {
			t.Fatalf("recovered package %x, want %x (slots=%v)", recovered, intsToBytesForTest(winnerPackage), slots[:8])
		}
	}
}

func TestFullFusePayloadMinimalRotationKeys(t *testing.T) {
	params := DefaultContractParams(32, 12)
	params.MinimalRotationKeys = true
	params.ProfileDim = 4
	params.PayloadSlotCount = 32

	shares := distributedSharesForTest(t, params, 3)
	evalKeys := distributedEvalKeysForTest(t, params, shares)

	initProfile := []float64{1, 0, 0, 0}
	loserProfile := []float64{0, 1, 0, 0}
	winnerProfile := []float64{1, 0, 0, 0}
	initCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, initProfile)
	if err != nil {
		t.Fatalf("encrypt initiator profile: %v", err)
	}
	loserCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, loserProfile)
	if err != nil {
		t.Fatalf("encrypt loser profile: %v", err)
	}
	winnerCT, err := EncryptCKKSForContract(params, shares[len(shares)-1].PublicKey, winnerProfile)
	if err != nil {
		t.Fatalf("encrypt winner profile: %v", err)
	}

	loserPackage := []int{0x11, 0x22, 0x33, 0x44}
	winnerPackage := []int{0xA5, 0x5A, 0xC3, 0x3C}
	ctWinner, err := FullFusePayloadCKKS(params, FullFuseRequest{
		InitiatorCiphertext:  initCT,
		CandidateCiphertexts: [][]byte{loserCT, winnerCT},
		CandidateLatQ:        []int{0, 0},
		CandidateLonQ:        []int{0, 0},
		CandidateBrownies:    []int{0, 0},
		CandidatePackages:    [][]int{loserPackage, winnerPackage},
		ProfileDim:           len(initProfile),
		Alpha:                0,
		Beta:                 1,
		Gamma:                0,
		Comparator:           "tanh_chebyshev",
		ComparatorDegree:     7,
		ComparatorGain:       40,
		ComparatorScale:      1,
		ComparatorBound:      1,
		SelectorSchedule:     "none",
		EvalKeys:             evalKeys,
		PackageBytes:         len(winnerPackage),
		PayloadSlotCount:     len(winnerPackage) * 8,
		MinimalRotationKeys:  true,
	})
	if err != nil {
		t.Fatalf("minimal full fuse payload: %v", err)
	}
	partials := make([][]byte, 0, len(shares))
	for _, share := range shares {
		partial, err := PartialDecryptCKKSForContract(params, ctWinner, share.SecretKeyShare, share.Lead)
		if err != nil {
			t.Fatalf("partial decrypt lead=%v: %v", share.Lead, err)
		}
		partials = append(partials, partial)
	}
	slots, err := FuseCKKSPartialsForContract(params, partials, len(winnerPackage)*8)
	if err != nil {
		t.Fatalf("fuse minimal payload partials: %v", err)
	}
	recovered := slotsToBytesForTest(slots, len(winnerPackage))
	for i, want := range winnerPackage {
		if recovered[i] != byte(want) {
			t.Fatalf("minimal-mode recovered %x, want %x (slots=%v)",
				recovered, intsToBytesForTest(winnerPackage), slots[:8])
		}
	}
}

func slotsToBytesForTest(slots []float64, n int) []byte {
	out := make([]byte, n)
	for bit := 0; bit < n*8 && bit < len(slots); bit++ {
		if slots[bit] >= 0.5 {
			out[bit/8] |= 1 << uint(7-(bit%8))
		}
	}
	return out
}

func intsToBytesForTest(values []int) []byte {
	out := make([]byte, len(values))
	for i, value := range values {
		out[i] = byte(value)
	}
	return out
}

func distributedSharesForTest(t *testing.T, params ContractParams, n int) []DistributedKeyShare {
	t.Helper()
	shares := make([]DistributedKeyShare, n)
	var err error
	shares[0], err = DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("first keygen share: %v", err)
	}
	for i := 1; i < n; i++ {
		shares[i], err = DistributedKeyGenNext(params, shares[i-1].PublicKey)
		if err != nil {
			t.Fatalf("keygen share %d: %v", i, err)
		}
	}
	return shares
}

func distributedEvalKeysForTest(t *testing.T, params ContractParams, shares []DistributedKeyShare) EvalKeyFinal {
	t.Helper()
	lead, err := EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		t.Fatalf("eval-key round1 lead: %v", err)
	}
	publicKeys := make([][]byte, len(shares))
	multRound1 := make([][]byte, len(shares))
	sumRound1 := make([][]byte, len(shares))
	publicKeys[0] = shares[0].PublicKey
	multRound1[0] = lead.EvalMultBase
	sumRound1[0] = lead.EvalSumBase
	for i := 1; i < len(shares); i++ {
		publicKeys[i] = shares[i].PublicKey
		round1, err := EvalKeyRound1Participant(params, shares[i].SecretKeyShare, lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			t.Fatalf("eval-key round1 participant %d: %v", i, err)
		}
		multRound1[i] = round1.EvalMultSwitchShare
		sumRound1[i] = round1.EvalSumShare
	}
	combinedRound1, err := CombineEvalKeyRound1(params, publicKeys, multRound1, sumRound1)
	if err != nil {
		t.Fatalf("combine eval-key round1: %v", err)
	}

	finalShares := make([][]byte, len(shares))
	finalPK := shares[len(shares)-1].PublicKey
	for i := range shares {
		round2, err := EvalKeyRound2Participant(params, shares[i].SecretKeyShare, combinedRound1.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			t.Fatalf("eval-key round2 participant %d: %v", i, err)
		}
		finalShares[i] = round2.EvalMultFinalShare
	}
	final, err := CombineEvalKeyRound2(params, finalPK, finalShares, combinedRound1.EvalSumFinal)
	if err != nil {
		t.Fatalf("combine eval-key round2: %v", err)
	}
	return final
}
