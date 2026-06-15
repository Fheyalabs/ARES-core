// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

/*
#include "openfhe_wrapper.h"
#include <stdlib.h>
*/
import "C"

import "fmt"

// CombineEvalSumSharesIncremental folds the eval-sum (rotation) key shares one at a
// time: the lead base seeds the accumulator and each participant share is
// deserialized, folded, and freed before the next, so peak RAM is the accumulator
// plus one share instead of all N rotation-key maps resident at once (the
// CombineEvalSumKeys path). The result is byte-identical to the all-at-once combine.
// publicKeys[0] is the lead and evalSumShares[0] is the lead base; [1:] are the
// participant shares, in the same order CombineEvalKeyRound1 uses.
func CombineEvalSumSharesIncremental(params ContractParams, publicKeys [][]byte, evalSumShares [][]byte) ([]byte, error) {
	if len(publicKeys) != len(evalSumShares) || len(evalSumShares) == 0 {
		return nil, fmt.Errorf("public-key and eval-sum share counts must match and be non-empty")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)
	return combineEvalSumIncremental(ctx, publicKeys, evalSumShares)
}

// combineEvalSumIncremental folds shares into a live accumulator one at a time, so
// only the accumulator and the single share being folded are resident.
func combineEvalSumIncremental(ctx C.CryptoContextHandle, pkBytes, shareBytes [][]byte) ([]byte, error) {
	seed, err := deserializeRotKey(ctx, shareBytes[0])
	if err != nil {
		return nil, err
	}
	accum := C.EvalSumCombineStart(seed)
	C.FreeRotKey(seed)
	if accum == nil {
		return nil, fmt.Errorf("eval-sum combine start failed")
	}
	defer C.FreeRotKey(accum)
	for i := 1; i < len(shareBytes); i++ {
		pk, err := deserializePublicKey(ctx, pkBytes[i])
		if err != nil {
			return nil, err
		}
		share, err := deserializeRotKey(ctx, shareBytes[i])
		if err != nil {
			C.FreePublicKey(pk)
			return nil, err
		}
		rc := C.EvalSumCombineFold(ctx, accum, pk, share)
		C.FreeRotKey(share) // freed immediately -> peak bounded to accumulator + one share
		C.FreePublicKey(pk)
		if rc != 0 {
			return nil, fmt.Errorf("eval-sum combine fold %d failed", i)
		}
	}
	return serializeRotKey(accum)
}

// combineEvalSumAllAtOnce is the resident reference path (every share deserialized
// at once); used by the correctness test to compare against the incremental fold.
func combineEvalSumAllAtOnce(ctx C.CryptoContextHandle, pkBytes, shareBytes [][]byte) ([]byte, error) {
	n := len(shareBytes)
	pks := make([]C.PublicKeyHandle, n)
	shares := make([]C.RotKeyHandle, n)
	defer func() {
		for i := range pks {
			if pks[i] != nil {
				C.FreePublicKey(pks[i])
			}
		}
		for i := range shares {
			if shares[i] != nil {
				C.FreeRotKey(shares[i])
			}
		}
	}()
	for i := 0; i < n; i++ {
		pk, err := deserializePublicKey(ctx, pkBytes[i])
		if err != nil {
			return nil, err
		}
		pks[i] = pk
		share, err := deserializeRotKey(ctx, shareBytes[i])
		if err != nil {
			return nil, err
		}
		shares[i] = share
	}
	var out C.RotKeyHandle
	if rc := C.CombineEvalSumKeys(ctx, &pks[0], &shares[0], C.int(n), &out); rc != 0 {
		return nil, fmt.Errorf("combine eval-sum all-at-once failed")
	}
	defer C.FreeRotKey(out)
	return serializeRotKey(out)
}

// incrementalCombineResult holds the two serialized joint keys a cgo-free test compares.
type incrementalCombineResult struct {
	allAtOnce   []byte
	incremental []byte
}

// runIncrementalCombineCheck runs a 3-party eval-sum keygen, then combines the lead
// base plus two participant shares both all-at-once and incrementally, returning the
// two serialized joint keys so a cgo-free test can assert they are identical.
func runIncrementalCombineCheck(params ContractParams) (res incrementalCombineResult, err error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return res, err
	}
	defer C.FreeCryptoContext(ctx)

	var pk0, pk1, pk2 C.PublicKeyHandle
	var sk0, sk1, sk2 C.SecretKeyShareHandle
	if rc := C.KeyGenFirst(ctx, &pk0, &sk0); rc != 0 {
		return res, fmt.Errorf("keygen first failed")
	}
	defer C.FreePublicKey(pk0)
	defer C.FreeSecretKeyShare(sk0)
	if rc := C.KeyGenNext(ctx, pk0, &pk1, &sk1); rc != 0 {
		return res, fmt.Errorf("keygen next 1 failed")
	}
	defer C.FreePublicKey(pk1)
	defer C.FreeSecretKeyShare(sk1)
	if rc := C.KeyGenNext(ctx, pk1, &pk2, &sk2); rc != 0 {
		return res, fmt.Errorf("keygen next 2 failed")
	}
	defer C.FreePublicKey(pk2)
	defer C.FreeSecretKeyShare(sk2)

	var base, s1, s2 C.RotKeyHandle
	if rc := C.EvalSumKeyGenLead(ctx, sk0, &base); rc != 0 {
		return res, fmt.Errorf("eval-sum lead failed")
	}
	defer C.FreeRotKey(base)
	if rc := C.EvalSumKeyShare(ctx, sk1, base, pk1, &s1); rc != 0 {
		return res, fmt.Errorf("eval-sum share 1 failed")
	}
	defer C.FreeRotKey(s1)
	if rc := C.EvalSumKeyShare(ctx, sk2, base, pk2, &s2); rc != 0 {
		return res, fmt.Errorf("eval-sum share 2 failed")
	}
	defer C.FreeRotKey(s2)

	baseBytes, err := serializeRotKey(base)
	if err != nil {
		return res, err
	}
	s1Bytes, err := serializeRotKey(s1)
	if err != nil {
		return res, err
	}
	s2Bytes, err := serializeRotKey(s2)
	if err != nil {
		return res, err
	}
	pk0Bytes, err := serializePublicKey(pk0)
	if err != nil {
		return res, err
	}
	pk1Bytes, err := serializePublicKey(pk1)
	if err != nil {
		return res, err
	}
	pk2Bytes, err := serializePublicKey(pk2)
	if err != nil {
		return res, err
	}

	pkB := [][]byte{pk0Bytes, pk1Bytes, pk2Bytes}
	shB := [][]byte{baseBytes, s1Bytes, s2Bytes}
	if res.allAtOnce, err = combineEvalSumAllAtOnce(ctx, pkB, shB); err != nil {
		return res, err
	}
	if res.incremental, err = combineEvalSumIncremental(ctx, pkB, shB); err != nil {
		return res, err
	}
	return res, nil
}

// EvalSumIncrementalFold folds eval-sum (rotation) key shares one at a time into a
// live accumulator, so the caller can generate a participant share, fold it, nil
// the share's []byte, and repeat — peak Go-side RAM is the accumulator plus one
// share, not all N shares resident at once.
type EvalSumIncrementalFold struct {
	ctx   C.CryptoContextHandle
	accum C.RotKeyHandle
}

// NewEvalSumIncrementalFold creates an incremental eval-sum fold accumulator
// seeded with the lead base. The caller must call Finalize() to free the
// underlying C handles.
func NewEvalSumIncrementalFold(params ContractParams, leadBase []byte) (*EvalSumIncrementalFold, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	seed, err := deserializeRotKey(ctx, leadBase)
	if err != nil {
		C.FreeCryptoContext(ctx)
		return nil, err
	}
	accum := C.EvalSumCombineStart(seed)
	C.FreeRotKey(seed)
	if accum == nil {
		C.FreeCryptoContext(ctx)
		return nil, fmt.Errorf("eval-sum combine start failed")
	}
	return &EvalSumIncrementalFold{ctx: ctx, accum: accum}, nil
}

// Fold deserializes one participant's eval-sum share, folds it into the
// accumulator, and frees the C++ key before returning.
func (f *EvalSumIncrementalFold) Fold(publicKey, evalSumShare []byte) error {
	pk, err := deserializePublicKey(f.ctx, publicKey)
	if err != nil {
		return err
	}
	share, err := deserializeRotKey(f.ctx, evalSumShare)
	if err != nil {
		C.FreePublicKey(pk)
		return err
	}
	rc := C.EvalSumCombineFold(f.ctx, f.accum, pk, share)
	C.FreeRotKey(share)
	C.FreePublicKey(pk)
	if rc != 0 {
		return fmt.Errorf("eval-sum combine fold failed")
	}
	return nil
}

// Finalize serializes the accumulator and frees all C handles.
func (f *EvalSumIncrementalFold) Finalize() ([]byte, error) {
	defer C.FreeCryptoContext(f.ctx)
	defer C.FreeRotKey(f.accum)
	return serializeRotKey(f.accum)
}
