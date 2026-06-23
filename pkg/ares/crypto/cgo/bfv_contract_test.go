// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import "testing"

func TestBFVPackedIntThresholdRoundTrip(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	ct, err := EncryptBFVForContract(params, second.PublicKey, []int64{-3, 0, 42, 65536})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	p0, err := PartialDecryptBFVForContract(params, ct, first.SecretKeyShare, true)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := PartialDecryptBFVForContract(params, ct, second.SecretKeyShare, false)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	got, err := FuseBFVPartialsForContract(params, [][]byte{p0, p1}, 4)
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}
	want := []int64{-3, 0, 42, -1}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slot %d = %d, want %d (all slots %v)", i, got[i], want[i], got)
		}
	}
}

func TestBFVEvalKeyRounds(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	r1Lead, err := BFVEvalKeyRound1Lead(params, first.SecretKeyShare)
	if err != nil {
		t.Fatalf("round1 lead: %v", err)
	}
	r1Part, err := BFVEvalKeyRound1Participant(params, second.SecretKeyShare, r1Lead.EvalMultBase, r1Lead.EvalSumBase, second.PublicKey)
	if err != nil {
		t.Fatalf("round1 participant: %v", err)
	}
	r1, err := BFVCombineEvalKeyRound1(params,
		[][]byte{first.PublicKey, second.PublicKey},
		[][]byte{r1Lead.EvalMultBase, r1Part.EvalMultSwitchShare},
		[][]byte{r1Lead.EvalSumBase, r1Part.EvalSumShare},
	)
	if err != nil {
		t.Fatalf("combine round1: %v", err)
	}
	r20, err := BFVEvalKeyRound2Participant(params, first.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, true)
	if err != nil {
		t.Fatalf("round2 lead: %v", err)
	}
	r21, err := BFVEvalKeyRound2Participant(params, second.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, false)
	if err != nil {
		t.Fatalf("round2 participant: %v", err)
	}
	final, err := BFVCombineEvalKeyRound2(params, second.PublicKey, [][]byte{r20.EvalMultFinalShare, r21.EvalMultFinalShare}, r1.EvalSumFinal)
	if err != nil {
		t.Fatalf("combine round2: %v", err)
	}
	if len(final.EvalMultFinal) == 0 || len(final.EvalSumFinal) == 0 {
		t.Fatalf("empty final eval keys: %+v", final)
	}
}

func TestBFVEvalProductSum(t *testing.T) {
	if err := SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	params := BFVContractParams{
		RingDim:             8192,
		MultiplicativeDepth: 4,
		PlaintextModulus:    65537,
		BatchSize:           8,
	}
	first, err := BFVDistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := BFVDistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}
	evalKeys := buildBFVEvalKeysForTest(t, params, first, second)
	left, err := EncryptBFVForContract(params, second.PublicKey, []int64{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("encrypt left: %v", err)
	}
	right, err := EncryptBFVForContract(params, second.PublicKey, []int64{5, 6, 7, 8})
	if err != nil {
		t.Fatalf("encrypt right: %v", err)
	}
	dot, err := EvalProductSumBFVForContract(params, evalKeys, left, right, 4)
	if err != nil {
		t.Fatalf("eval product sum: %v", err)
	}
	p0, err := PartialDecryptBFVForContract(params, dot, first.SecretKeyShare, true)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := PartialDecryptBFVForContract(params, dot, second.SecretKeyShare, false)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	got, err := FuseBFVPartialsForContract(params, [][]byte{p0, p1}, 1)
	if err != nil {
		t.Fatalf("fuse: %v", err)
	}
	if got[0] != 70 {
		t.Fatalf("dot = %d, want 70", got[0])
	}
}

func buildBFVEvalKeysForTest(t *testing.T, params BFVContractParams, first, second DistributedKeyShare) EvalKeyFinal {
	t.Helper()
	r1Lead, err := BFVEvalKeyRound1Lead(params, first.SecretKeyShare)
	if err != nil {
		t.Fatalf("round1 lead: %v", err)
	}
	r1Part, err := BFVEvalKeyRound1Participant(params, second.SecretKeyShare, r1Lead.EvalMultBase, r1Lead.EvalSumBase, second.PublicKey)
	if err != nil {
		t.Fatalf("round1 participant: %v", err)
	}
	r1, err := BFVCombineEvalKeyRound1(params,
		[][]byte{first.PublicKey, second.PublicKey},
		[][]byte{r1Lead.EvalMultBase, r1Part.EvalMultSwitchShare},
		[][]byte{r1Lead.EvalSumBase, r1Part.EvalSumShare},
	)
	if err != nil {
		t.Fatalf("combine round1: %v", err)
	}
	r20, err := BFVEvalKeyRound2Participant(params, first.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, true)
	if err != nil {
		t.Fatalf("round2 lead: %v", err)
	}
	r21, err := BFVEvalKeyRound2Participant(params, second.SecretKeyShare, r1.EvalMultJoined, second.PublicKey, false)
	if err != nil {
		t.Fatalf("round2 participant: %v", err)
	}
	final, err := BFVCombineEvalKeyRound2(params, second.PublicKey, [][]byte{r20.EvalMultFinalShare, r21.EvalMultFinalShare}, r1.EvalSumFinal)
	if err != nil {
		t.Fatalf("combine round2: %v", err)
	}
	return final
}
