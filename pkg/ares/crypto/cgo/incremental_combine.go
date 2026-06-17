// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

/*
#include "openfhe_wrapper.h"
#include <stdlib.h>
*/
import "C"

import "fmt"

// IndexedEvalSumKey is one serialized single-index eval-sum/rotation key.
// Key contains the normal OpenFHE binary RotKey map serialization for exactly
// one rotation index.
type IndexedEvalSumKey struct {
	Index int
	Key   []byte
}

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

// CombineEvalKeyRound1PerIndex combines the normal one-per-party eval-mult
// round-1 shares with eval-sum shares supplied as one RotKey per rotation index.
// evalSumSharesByParty is ordered like publicKeys/evalMultShares: party 0 is the
// lead base, parties 1..N-1 are participant shares. Every party must provide the
// same index set.
func CombineEvalKeyRound1PerIndex(params ContractParams, publicKeys [][]byte, evalMultShares [][]byte, evalSumSharesByParty [][]IndexedEvalSumKey) (EvalKeyRound1Combined, error) {
	if len(publicKeys) == 0 || len(publicKeys) != len(evalMultShares) || len(publicKeys) != len(evalSumSharesByParty) {
		return EvalKeyRound1Combined{}, fmt.Errorf("public/eval-mult/eval-sum party counts must match and be non-empty")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	defer C.FreeCryptoContext(ctx)
	return combineEvalKeyRound1PerIndex(ctx, publicKeys, evalMultShares, evalSumSharesByParty)
}

func combineEvalKeyRound1PerIndex(ctx C.CryptoContextHandle, publicKeys [][]byte, evalMultShares [][]byte, evalSumSharesByParty [][]IndexedEvalSumKey) (EvalKeyRound1Combined, error) {
	if len(publicKeys) == 0 || len(publicKeys) != len(evalMultShares) || len(publicKeys) != len(evalSumSharesByParty) {
		return EvalKeyRound1Combined{}, fmt.Errorf("public/eval-mult/eval-sum party counts must match and be non-empty")
	}
	pks, freePKs, err := deserializePublicKeys(ctx, publicKeys)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	defer freePKs()
	multShares, freeMultShares, err := deserializeEvalMultKeys(ctx, evalMultShares)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	defer freeMultShares()

	var joined C.EvalMultKeyHandle
	if rc := C.CombineEvalMultSwitchShares(ctx, &pks[0], &multShares[0], C.int(len(multShares)), &joined); rc != 0 {
		return EvalKeyRound1Combined{}, fmt.Errorf("eval-mult switch-share combination failed")
	}
	defer C.FreeEvalMultKey(joined)
	joinedBytes, err := serializeEvalMultKey(joined)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}

	sumFinalBytes, err := combineEvalSumPerIndex(ctx, publicKeys, evalSumSharesByParty)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	return EvalKeyRound1Combined{EvalMultJoined: joinedBytes, EvalSumFinal: sumFinalBytes}, nil
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

func combineEvalSumPerIndex(ctx C.CryptoContextHandle, publicKeys [][]byte, byParty [][]IndexedEvalSumKey) ([]byte, error) {
	indices, keyedByParty, err := validateIndexedEvalSumShares(byParty)
	if err != nil {
		return nil, err
	}
	var final C.RotKeyHandle
	defer func() {
		if final != nil {
			C.FreeRotKey(final)
		}
	}()

	for _, index := range indices {
		seed, err := deserializeRotKey(ctx, keyedByParty[0][index])
		if err != nil {
			return nil, fmt.Errorf("deserialize lead eval-sum index %d: %w", index, err)
		}
		accum := C.EvalSumCombineStart(seed)
		C.FreeRotKey(seed)
		if accum == nil {
			return nil, fmt.Errorf("eval-sum combine start index %d failed", index)
		}

		for party := 1; party < len(keyedByParty); party++ {
			pk, err := deserializePublicKey(ctx, publicKeys[party])
			if err != nil {
				C.FreeRotKey(accum)
				return nil, fmt.Errorf("deserialize public key party %d: %w", party, err)
			}
			share, err := deserializeRotKey(ctx, keyedByParty[party][index])
			if err != nil {
				C.FreePublicKey(pk)
				C.FreeRotKey(accum)
				return nil, fmt.Errorf("deserialize eval-sum party %d index %d: %w", party, index, err)
			}
			rc := C.EvalSumCombineFold(ctx, accum, pk, share)
			C.FreeRotKey(share)
			C.FreePublicKey(pk)
			if rc != 0 {
				C.FreeRotKey(accum)
				return nil, fmt.Errorf("eval-sum combine fold party %d index %d failed", party, index)
			}
		}

		if final == nil {
			final = accum
			continue
		}
		if rc := C.MergeEvalSumKeyMaps(final, accum); rc != 0 {
			C.FreeRotKey(accum)
			return nil, fmt.Errorf("merge eval-sum index %d failed", index)
		}
		C.FreeRotKey(accum)
	}

	if final == nil {
		return nil, fmt.Errorf("no per-index eval-sum keys to combine")
	}
	return serializeRotKey(final)
}

func validateIndexedEvalSumShares(byParty [][]IndexedEvalSumKey) ([]int, []map[int][]byte, error) {
	if len(byParty) == 0 {
		return nil, nil, fmt.Errorf("at least one eval-sum party is required")
	}
	indices := make([]int, 0, len(byParty[0]))
	keyedByParty := make([]map[int][]byte, len(byParty))
	var required map[int]struct{}
	for party, shares := range byParty {
		if len(shares) == 0 {
			return nil, nil, fmt.Errorf("eval-sum party %d submitted no per-index keys", party)
		}
		keyed := make(map[int][]byte, len(shares))
		for _, share := range shares {
			if len(share.Key) == 0 {
				return nil, nil, fmt.Errorf("eval-sum party %d index %d has empty key", party, share.Index)
			}
			if _, exists := keyed[share.Index]; exists {
				return nil, nil, fmt.Errorf("eval-sum party %d duplicated index %d", party, share.Index)
			}
			keyed[share.Index] = share.Key
			if party == 0 {
				indices = append(indices, share.Index)
			}
		}
		if party == 0 {
			required = make(map[int]struct{}, len(keyed))
			for idx := range keyed {
				required[idx] = struct{}{}
			}
		} else {
			if len(keyed) != len(required) {
				return nil, nil, fmt.Errorf("eval-sum party %d submitted %d indices, want %d", party, len(keyed), len(required))
			}
			for idx := range required {
				if _, ok := keyed[idx]; !ok {
					return nil, nil, fmt.Errorf("eval-sum party %d missing index %d", party, idx)
				}
			}
			for idx := range keyed {
				if _, ok := required[idx]; !ok {
					return nil, nil, fmt.Errorf("eval-sum party %d submitted unexpected index %d", party, idx)
				}
			}
		}
		keyedByParty[party] = keyed
	}
	return indices, keyedByParty, nil
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
	ctx     C.CryptoContextHandle
	accum   C.RotKeyHandle
	ownsCtx bool // true if Finalize should free ctx (created via NewEvalSumIncrementalFold)
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
	return &EvalSumIncrementalFold{ctx: ctx, accum: accum, ownsCtx: true}, nil
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

// Finalize serializes the accumulator and frees C handles owned by this fold.
func (f *EvalSumIncrementalFold) Finalize() ([]byte, error) {
	if f.ownsCtx {
		defer C.FreeCryptoContext(f.ctx)
	}
	defer C.FreeRotKey(f.accum)
	return serializeRotKey(f.accum)
}
