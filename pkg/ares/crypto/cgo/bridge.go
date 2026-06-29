// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

/*
// OpenFHE 1.5.x does not ship pkg-config files (it uses CMake's
// find_package). Platform-specific include and library paths are
// declared in bridge_darwin.go and bridge_linux.go.
//
// For a non-default install prefix, append flags via CGO_CXXFLAGS
// and CGO_LDFLAGS:
//
//	export CGO_CXXFLAGS="-I/your/openfhe/include/openfhe -I/your/openfhe/include/openfhe/pke -I/your/openfhe/include/openfhe/core -I/your/openfhe/include/openfhe/cereal -I/your/openfhe/include/openfhe/binfhe"
//	export CGO_LDFLAGS="-L/your/openfhe/lib -Wl,-rpath,/your/openfhe/lib"
//	go build -tags openfhe ./...
//
// pkg-config users: install pkg-config/openfhe.pc.in (substitute
// @prefix@, drop into $PKG_CONFIG_PATH), then switch the cgo
// directives in bridge_*.go to `#cgo pkg-config: OpenFHE`.
#cgo CXXFLAGS: -std=c++17
#include <stdlib.h>
#include "openfhe_wrapper.h"
*/
import "C"

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"unsafe"
)

// INVARIANT (read before adding a new exported function in this file):
//
// Every exported function that passes a Go slice through cgo via
// `(*C.X)(unsafe.Pointer(&slice[0]))` MUST guard against `len(slice)
// == 0` at function entry. Indexing an empty slice — even just for
// the address — panics. The convention across this file is to return
// `fmt.Errorf("<name> is required")` (or the equivalent
// `<name>_count` check on `[][]byte` arguments) BEFORE the C call.
//
// The single helper `requireNonEmptyBytes` below is provided for the
// common case; multi-element checks stay inline at the call site so
// the error message can name the specific slice that failed.
func requireNonEmptyBytes(name string, b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("%s is required (empty slice)", name)
	}
	return nil
}

type ContractParams struct {
	RingDim       uint32
	ScalingFactor float64
	Depth         uint32
	// MinimalRotationKeys opts into dimension-parameterized rotation-key generation:
	// only the at-index keys ProfileDim/PayloadSlotCount need are produced. Default
	// false keeps the full-batch EvalSum + broadcast keygen. ProfileDim and
	// PayloadSlotCount are read only when MinimalRotationKeys is true.
	MinimalRotationKeys bool
	ProfileDim          int
	PayloadSlotCount    int
	// EvalSumOnlyRotationKeys opts into the chunked-fusion rotation set: the context is
	// built with batch_size = next_pow2(ProfileDim) and the threshold eval-sum keygen
	// produces only the replicating EvalSumKeyGen map (7 keys at dim 128), no broadcast.
	// Use with ChunkedFusePayloadCKKS. Mutually exclusive with MinimalRotationKeys.
	EvalSumOnlyRotationKeys bool
}

type BFVContractParams struct {
	RingDim             uint32
	MultiplicativeDepth uint32
	PlaintextModulus    uint64
	BatchSize           int
}

type DistributedKeyShare struct {
	PublicKey      []byte
	SecretKeyShare []byte
	Lead           bool
}

type EvalKeyRound1LeadShare struct {
	EvalMultBase []byte
	EvalSumBase  []byte
}

type EvalKeyRound1ParticipantShare struct {
	EvalMultSwitchShare []byte
	EvalSumShare        []byte
}

type EvalKeyRound1Combined struct {
	EvalMultJoined []byte
	EvalSumFinal   []byte
}

type EvalKeyRound2ParticipantShare struct {
	EvalMultFinalShare []byte
}

type EvalKeyFinal struct {
	EvalMultFinal []byte
	EvalSumFinal  []byte
}

func DefaultContractParams(profileDim int, depth uint32) ContractParams {
	ringDim := uint32(1024)
	if profileDim > 0 {
		ringDim = uint32(1)
		for ringDim < uint32(profileDim*2) {
			ringDim <<= 1
		}
		if ringDim < 1024 {
			ringDim = 1024
		}
	}
	if depth == 0 {
		depth = 30
	}
	return ContractParams{
		RingDim:       ringDim,
		ScalingFactor: float64(uint64(1) << 50),
		Depth:         depth,
	}
}

type ScoreRequest struct {
	InitiatorProfile  []float64
	InitiatorLatQ     int
	InitiatorLonQ     int
	CandidateProfiles [][]float64
	CandidateLatQ     []int
	CandidateLonQ     []int
	CandidateBrownies []int
	CandidatePackages [][]int
	Alpha             float64
	Beta              float64
	Gamma             float64
	DistanceFunction  string
	Comparator        string
	ComparatorDegree  int
	ComparatorGain    float64
	ComparatorScale   float64
	ComparatorBound   float64
	MaskMode          string
	SelectorSchedule  string
	ScalingModSize    int
	FirstModSize      int
	PayloadSlotCount  int
}

type ScoreResult struct {
	Scores        []float64
	MaskValues    []float64
	PayloadValues []float64
	WinnerIndex   int
	WinnerScore   float64
}

type FullFuseRequest struct {
	InitiatorCiphertext  []byte
	InitiatorLatQ        int
	InitiatorLonQ        int
	CandidateCiphertexts [][]byte
	CandidateLatQ        []int
	CandidateLonQ        []int
	CandidateBrownies    []int
	CandidatePackages    [][]int
	ProfileDim           int
	Alpha                float64
	Beta                 float64
	Gamma                float64
	Comparator           string
	ComparatorDegree     int
	ComparatorGain       float64
	ComparatorScale      float64
	ComparatorBound      float64
	SelectorSchedule     string
	EvalKeys             EvalKeyFinal
	PackageBytes         int
	PayloadSlotCount     int
	MinimalRotationKeys  bool
}

func DistributedKeyGenFirst(params ContractParams) (DistributedKeyShare, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	var pk C.PublicKeyHandle
	var sk C.SecretKeyShareHandle
	if rc := C.KeyGenFirst(ctx, &pk, &sk); rc != 0 {
		return DistributedKeyShare{}, fmt.Errorf("distributed keygen first failed")
	}
	defer C.FreePublicKey(pk)
	defer C.FreeSecretKeyShare(sk)

	pkBytes, err := serializePublicKey(pk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	skBytes, err := serializeSecretKeyShare(sk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	return DistributedKeyShare{PublicKey: pkBytes, SecretKeyShare: skBytes, Lead: true}, nil
}

func BFVDistributedKeyGenFirst(params BFVContractParams) (DistributedKeyShare, error) {
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	var pk C.PublicKeyHandle
	var sk C.SecretKeyShareHandle
	if rc := C.KeyGenFirst(ctx, &pk, &sk); rc != 0 {
		return DistributedKeyShare{}, fmt.Errorf("BFV distributed keygen first failed")
	}
	defer C.FreePublicKey(pk)
	defer C.FreeSecretKeyShare(sk)

	pkBytes, err := serializePublicKey(pk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	skBytes, err := serializeSecretKeyShare(sk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	return DistributedKeyShare{PublicKey: pkBytes, SecretKeyShare: skBytes, Lead: true}, nil
}

func BFVDistributedKeyGenNext(params BFVContractParams, prevPublicKey []byte) (DistributedKeyShare, error) {
	if len(prevPublicKey) == 0 {
		return DistributedKeyShare{}, fmt.Errorf("previous public key is required")
	}
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	prev, err := deserializePublicKey(ctx, prevPublicKey)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	defer C.FreePublicKey(prev)

	var pk C.PublicKeyHandle
	var sk C.SecretKeyShareHandle
	if rc := C.KeyGenNext(ctx, prev, &pk, &sk); rc != 0 {
		return DistributedKeyShare{}, fmt.Errorf("BFV distributed keygen next failed")
	}
	defer C.FreePublicKey(pk)
	defer C.FreeSecretKeyShare(sk)

	pkBytes, err := serializePublicKey(pk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	skBytes, err := serializeSecretKeyShare(sk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	return DistributedKeyShare{PublicKey: pkBytes, SecretKeyShare: skBytes, Lead: false}, nil
}

func DistributedKeyGenNext(params ContractParams, prevPublicKey []byte) (DistributedKeyShare, error) {
	if len(prevPublicKey) == 0 {
		return DistributedKeyShare{}, fmt.Errorf("previous public key is required")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	prev, err := deserializePublicKey(ctx, prevPublicKey)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	defer C.FreePublicKey(prev)

	var pk C.PublicKeyHandle
	var sk C.SecretKeyShareHandle
	if rc := C.KeyGenNext(ctx, prev, &pk, &sk); rc != 0 {
		return DistributedKeyShare{}, fmt.Errorf("distributed keygen next failed")
	}
	defer C.FreePublicKey(pk)
	defer C.FreeSecretKeyShare(sk)

	pkBytes, err := serializePublicKey(pk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	skBytes, err := serializeSecretKeyShare(sk)
	if err != nil {
		return DistributedKeyShare{}, err
	}
	return DistributedKeyShare{PublicKey: pkBytes, SecretKeyShare: skBytes, Lead: false}, nil
}

func EvalKeyRound1Lead(params ContractParams, secretKeyShare []byte) (EvalKeyRound1LeadShare, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, true)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)

	var mult C.EvalMultKeyHandle
	if rc := C.EvalMultKeyGenLead(ctx, sk, &mult); rc != 0 {
		return EvalKeyRound1LeadShare{}, fmt.Errorf("eval-mult lead key generation failed")
	}
	defer C.FreeEvalMultKey(mult)
	multBytes, err := serializeEvalMultKey(mult)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}

	var sum C.RotKeyHandle
	if rc := C.EvalSumKeyGenLead(ctx, sk, &sum); rc != 0 {
		return EvalKeyRound1LeadShare{}, fmt.Errorf("eval-sum lead key generation failed")
	}
	defer C.FreeRotKey(sum)
	sumBytes, err := serializeRotKey(sum)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	return EvalKeyRound1LeadShare{EvalMultBase: multBytes, EvalSumBase: sumBytes}, nil
}

func EvalKeyRound1Participant(params ContractParams, secretKeyShare, evalMultBase, evalSumBase, ownPublicKey []byte) (EvalKeyRound1ParticipantShare, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, false)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)
	multBase, err := deserializeEvalMultKey(ctx, evalMultBase)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeEvalMultKey(multBase)
	sumBase, err := deserializeRotKey(ctx, evalSumBase)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeRotKey(sumBase)
	ownPK, err := deserializePublicKey(ctx, ownPublicKey)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreePublicKey(ownPK)

	var multShare C.EvalMultKeyHandle
	if rc := C.EvalMultKeySwitchShare(ctx, sk, multBase, &multShare); rc != 0 {
		return EvalKeyRound1ParticipantShare{}, fmt.Errorf("eval-mult switch-share generation failed")
	}
	defer C.FreeEvalMultKey(multShare)
	multBytes, err := serializeEvalMultKey(multShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}

	var sumShare C.RotKeyHandle
	if rc := C.EvalSumKeyShare(ctx, sk, sumBase, ownPK, &sumShare); rc != 0 {
		return EvalKeyRound1ParticipantShare{}, fmt.Errorf("eval-sum share generation failed")
	}
	defer C.FreeRotKey(sumShare)
	sumBytes, err := serializeRotKey(sumShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	return EvalKeyRound1ParticipantShare{EvalMultSwitchShare: multBytes, EvalSumShare: sumBytes}, nil
}

func CombineEvalKeyRound1(params ContractParams, publicKeys [][]byte, evalMultShares [][]byte, evalSumShares [][]byte) (EvalKeyRound1Combined, error) {
	if len(publicKeys) == 0 || len(publicKeys) != len(evalMultShares) || len(publicKeys) != len(evalSumShares) {
		return EvalKeyRound1Combined{}, fmt.Errorf("public/eval-key share counts must match and be non-empty")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	defer C.FreeCryptoContext(ctx)

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
	if rc := C.CombineEvalMultSwitchShares(ctx, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.EvalMultKeyHandle)(unsafe.Pointer(&multShares[0])), C.int(len(multShares)), &joined); rc != 0 {
		return EvalKeyRound1Combined{}, fmt.Errorf("eval-mult switch-share combination failed")
	}
	defer C.FreeEvalMultKey(joined)
	joinedBytes, err := serializeEvalMultKey(joined)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}

	// Fold the eval-sum (rotation) shares one at a time so peak RAM is the
	// accumulator plus one share, not all N rotation-key maps resident at once;
	// byte-identical to the all-at-once CombineEvalSumKeys.
	sumFinalBytes, err := combineEvalSumIncremental(ctx, publicKeys, evalSumShares)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	return EvalKeyRound1Combined{EvalMultJoined: joinedBytes, EvalSumFinal: sumFinalBytes}, nil
}

// CombineEvalMultSwitchShares combines the N eval-mult switch-key shares into the
// joint eval-mult key (the relinearization key). This is the eval-mult half of
// CombineEvalKeyRound1; callers who fold eval-sum shares incrementally via
// NewEvalSumIncrementalFold use this to combine the (small) eval-mult shares.
func CombineEvalMultSwitchShares(params ContractParams, publicKeys [][]byte, evalMultShares [][]byte) ([]byte, error) {
	if len(publicKeys) == 0 || len(publicKeys) != len(evalMultShares) {
		return nil, fmt.Errorf("public/eval-mult share counts must match and be non-empty")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	pks, freePKs, err := deserializePublicKeys(ctx, publicKeys)
	if err != nil {
		return nil, err
	}
	defer freePKs()
	multShares, freeMultShares, err := deserializeEvalMultKeys(ctx, evalMultShares)
	if err != nil {
		return nil, err
	}
	defer freeMultShares()

	var joined C.EvalMultKeyHandle
	if rc := C.CombineEvalMultSwitchShares(ctx, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.EvalMultKeyHandle)(unsafe.Pointer(&multShares[0])), C.int(len(multShares)), &joined); rc != 0 {
		return nil, fmt.Errorf("eval-mult switch-share combination failed")
	}
	defer C.FreeEvalMultKey(joined)
	return serializeEvalMultKey(joined)
}

func EvalKeyRound2Participant(params ContractParams, secretKeyShare, evalMultJoined, finalPublicKey []byte, lead bool) (EvalKeyRound2ParticipantShare, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, lead)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)
	joined, err := deserializeEvalMultKey(ctx, evalMultJoined)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeEvalMultKey(joined)
	finalPK, err := deserializePublicKey(ctx, finalPublicKey)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreePublicKey(finalPK)

	var finalShare C.EvalMultKeyHandle
	if rc := C.EvalMultKeyFinalShare(ctx, sk, joined, finalPK, &finalShare); rc != 0 {
		return EvalKeyRound2ParticipantShare{}, fmt.Errorf("eval-mult final-share generation failed")
	}
	defer C.FreeEvalMultKey(finalShare)
	finalBytes, err := serializeEvalMultKey(finalShare)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	return EvalKeyRound2ParticipantShare{EvalMultFinalShare: finalBytes}, nil
}

func CombineEvalKeyRound2(params ContractParams, finalPublicKey []byte, evalMultFinalShares [][]byte, evalSumFinal []byte) (EvalKeyFinal, error) {
	if len(evalMultFinalShares) == 0 {
		return EvalKeyFinal{}, fmt.Errorf("at least one eval-mult final share is required")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer C.FreeCryptoContext(ctx)

	finalPK, err := deserializePublicKey(ctx, finalPublicKey)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer C.FreePublicKey(finalPK)
	finalShares, freeFinalShares, err := deserializeEvalMultKeys(ctx, evalMultFinalShares)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer freeFinalShares()

	var final C.EvalMultKeyHandle
	if rc := C.CombineEvalMultFinalShares(ctx, finalPK, (*C.EvalMultKeyHandle)(unsafe.Pointer(&finalShares[0])), C.int(len(finalShares)), &final); rc != 0 {
		return EvalKeyFinal{}, fmt.Errorf("eval-mult final-share combination failed")
	}
	defer C.FreeEvalMultKey(final)
	finalBytes, err := serializeEvalMultKey(final)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	return EvalKeyFinal{EvalMultFinal: finalBytes, EvalSumFinal: append([]byte(nil), evalSumFinal...)}, nil
}

func BFVEvalKeyRound1Lead(params BFVContractParams, secretKeyShare []byte) (EvalKeyRound1LeadShare, error) {
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, true)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)

	var mult C.EvalMultKeyHandle
	if rc := C.EvalMultKeyGenLead(ctx, sk, &mult); rc != 0 {
		return EvalKeyRound1LeadShare{}, fmt.Errorf("BFV eval-mult lead key generation failed")
	}
	defer C.FreeEvalMultKey(mult)
	multBytes, err := serializeEvalMultKey(mult)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}

	var sum C.RotKeyHandle
	if rc := C.EvalSumKeyGenLead(ctx, sk, &sum); rc != 0 {
		return EvalKeyRound1LeadShare{}, fmt.Errorf("BFV eval-sum lead key generation failed")
	}
	defer C.FreeRotKey(sum)
	sumBytes, err := serializeRotKey(sum)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	return EvalKeyRound1LeadShare{EvalMultBase: multBytes, EvalSumBase: sumBytes}, nil
}

func BFVEvalKeyRound1Participant(params BFVContractParams, secretKeyShare, evalMultBase, evalSumBase, ownPublicKey []byte) (EvalKeyRound1ParticipantShare, error) {
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, false)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)
	multBase, err := deserializeEvalMultKey(ctx, evalMultBase)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeEvalMultKey(multBase)
	sumBase, err := deserializeRotKey(ctx, evalSumBase)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeRotKey(sumBase)
	ownPK, err := deserializePublicKey(ctx, ownPublicKey)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreePublicKey(ownPK)

	var multShare C.EvalMultKeyHandle
	if rc := C.EvalMultKeySwitchShare(ctx, sk, multBase, &multShare); rc != 0 {
		return EvalKeyRound1ParticipantShare{}, fmt.Errorf("BFV eval-mult switch-share generation failed")
	}
	defer C.FreeEvalMultKey(multShare)
	multBytes, err := serializeEvalMultKey(multShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}

	var sumShare C.RotKeyHandle
	if rc := C.EvalSumKeyShare(ctx, sk, sumBase, ownPK, &sumShare); rc != 0 {
		return EvalKeyRound1ParticipantShare{}, fmt.Errorf("BFV eval-sum share generation failed")
	}
	defer C.FreeRotKey(sumShare)
	sumBytes, err := serializeRotKey(sumShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	return EvalKeyRound1ParticipantShare{EvalMultSwitchShare: multBytes, EvalSumShare: sumBytes}, nil
}

func BFVCombineEvalKeyRound1(params BFVContractParams, publicKeys [][]byte, evalMultShares [][]byte, evalSumShares [][]byte) (EvalKeyRound1Combined, error) {
	if len(publicKeys) == 0 || len(publicKeys) != len(evalMultShares) || len(publicKeys) != len(evalSumShares) {
		return EvalKeyRound1Combined{}, fmt.Errorf("public/eval-key share counts must match and be non-empty")
	}
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	defer C.FreeCryptoContext(ctx)

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
	if rc := C.CombineEvalMultSwitchShares(ctx, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.EvalMultKeyHandle)(unsafe.Pointer(&multShares[0])), C.int(len(multShares)), &joined); rc != 0 {
		return EvalKeyRound1Combined{}, fmt.Errorf("BFV eval-mult switch-share combination failed")
	}
	defer C.FreeEvalMultKey(joined)
	joinedBytes, err := serializeEvalMultKey(joined)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	sumFinalBytes, err := combineEvalSumIncremental(ctx, publicKeys, evalSumShares)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	return EvalKeyRound1Combined{EvalMultJoined: joinedBytes, EvalSumFinal: sumFinalBytes}, nil
}

func BFVEvalKeyRound2Participant(params BFVContractParams, secretKeyShare, evalMultJoined, finalPublicKey []byte, lead bool) (EvalKeyRound2ParticipantShare, error) {
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeCryptoContext(ctx)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, lead)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)
	joined, err := deserializeEvalMultKey(ctx, evalMultJoined)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeEvalMultKey(joined)
	finalPK, err := deserializePublicKey(ctx, finalPublicKey)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreePublicKey(finalPK)

	var finalShare C.EvalMultKeyHandle
	if rc := C.EvalMultKeyFinalShare(ctx, sk, joined, finalPK, &finalShare); rc != 0 {
		return EvalKeyRound2ParticipantShare{}, fmt.Errorf("BFV eval-mult final-share generation failed")
	}
	defer C.FreeEvalMultKey(finalShare)
	finalBytes, err := serializeEvalMultKey(finalShare)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	return EvalKeyRound2ParticipantShare{EvalMultFinalShare: finalBytes}, nil
}

func BFVCombineEvalKeyRound2(params BFVContractParams, finalPublicKey []byte, evalMultFinalShares [][]byte, evalSumFinal []byte) (EvalKeyFinal, error) {
	if len(evalMultFinalShares) == 0 {
		return EvalKeyFinal{}, fmt.Errorf("at least one eval-mult final share is required")
	}
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer C.FreeCryptoContext(ctx)

	finalPK, err := deserializePublicKey(ctx, finalPublicKey)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer C.FreePublicKey(finalPK)
	finalShares, freeFinalShares, err := deserializeEvalMultKeys(ctx, evalMultFinalShares)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer freeFinalShares()

	var final C.EvalMultKeyHandle
	if rc := C.CombineEvalMultFinalShares(ctx, finalPK, (*C.EvalMultKeyHandle)(unsafe.Pointer(&finalShares[0])), C.int(len(finalShares)), &final); rc != 0 {
		return EvalKeyFinal{}, fmt.Errorf("BFV eval-mult final-share combination failed")
	}
	defer C.FreeEvalMultKey(final)
	finalBytes, err := serializeEvalMultKey(final)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	return EvalKeyFinal{EvalMultFinal: finalBytes, EvalSumFinal: append([]byte(nil), evalSumFinal...)}, nil
}

func EvalProductSumForContract(params ContractParams, evalKeys EvalKeyFinal, leftCiphertext, rightCiphertext []byte, nSlots int) ([]byte, error) {
	if len(evalKeys.EvalMultFinal) == 0 || len(evalKeys.EvalSumFinal) == 0 {
		return nil, fmt.Errorf("eval-mult and eval-sum keys are required")
	}
	if nSlots <= 0 {
		return nil, fmt.Errorf("nSlots must be positive")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	multKey, err := deserializeEvalMultKey(ctx, evalKeys.EvalMultFinal)
	if err != nil {
		return nil, err
	}
	defer C.FreeEvalMultKey(multKey)
	if rc := C.InsertEvalMultKey(ctx, multKey); rc != 0 {
		return nil, fmt.Errorf("insert eval-mult key failed")
	}
	sumKey, err := deserializeRotKey(ctx, evalKeys.EvalSumFinal)
	if err != nil {
		return nil, err
	}
	defer C.FreeRotKey(sumKey)
	if rc := C.InsertEvalSumKey(ctx, sumKey); rc != 0 {
		return nil, fmt.Errorf("insert eval-sum key failed")
	}

	left, err := deserializeCiphertext(ctx, leftCiphertext)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(left)
	right, err := deserializeCiphertext(ctx, rightCiphertext)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(right)
	product := C.EvalMult(ctx, left, right)
	if product == nil {
		return nil, fmt.Errorf("eval-mult failed")
	}
	defer C.FreeCiphertext(product)
	sum := C.EvalSum(ctx, product, C.int(nSlots))
	if sum == nil {
		return nil, fmt.Errorf("eval-sum failed")
	}
	defer C.FreeCiphertext(sum)
	return serializeCiphertext(sum)
}

func EvalProductSumBFVForContract(params BFVContractParams, evalKeys EvalKeyFinal, leftCiphertext, rightCiphertext []byte, nSlots int) ([]byte, error) {
	if len(evalKeys.EvalMultFinal) == 0 || len(evalKeys.EvalSumFinal) == 0 {
		return nil, fmt.Errorf("eval-mult and eval-sum keys are required")
	}
	if nSlots <= 0 {
		return nil, fmt.Errorf("nSlots must be positive")
	}
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	multKey, err := deserializeEvalMultKey(ctx, evalKeys.EvalMultFinal)
	if err != nil {
		return nil, err
	}
	defer C.FreeEvalMultKey(multKey)
	if rc := C.InsertEvalMultKey(ctx, multKey); rc != 0 {
		return nil, fmt.Errorf("insert BFV eval-mult key failed")
	}
	sumKey, err := deserializeRotKey(ctx, evalKeys.EvalSumFinal)
	if err != nil {
		return nil, err
	}
	defer C.FreeRotKey(sumKey)
	if rc := C.InsertEvalSumKey(ctx, sumKey); rc != 0 {
		return nil, fmt.Errorf("insert BFV eval-sum key failed")
	}

	left, err := deserializeCiphertext(ctx, leftCiphertext)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(left)
	right, err := deserializeCiphertext(ctx, rightCiphertext)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(right)
	product := C.EvalMult(ctx, left, right)
	if product == nil {
		return nil, fmt.Errorf("BFV eval-mult failed")
	}
	defer C.FreeCiphertext(product)
	sum := C.EvalSum(ctx, product, C.int(nSlots))
	if sum == nil {
		return nil, fmt.Errorf("BFV eval-sum failed")
	}
	defer C.FreeCiphertext(sum)
	return serializeCiphertext(sum)
}

func FullFusePayloadCKKS(params ContractParams, req FullFuseRequest) ([]byte, error) {
	n := len(req.CandidateCiphertexts)
	if len(req.InitiatorCiphertext) == 0 {
		return nil, fmt.Errorf("initiator ciphertext is required")
	}
	if n == 0 {
		return nil, fmt.Errorf("at least one candidate ciphertext is required")
	}
	if len(req.CandidateLatQ) != n || len(req.CandidateLonQ) != n || len(req.CandidateBrownies) != n || len(req.CandidatePackages) != n {
		return nil, fmt.Errorf("candidate metadata counts must match ciphertext count")
	}
	if len(req.EvalKeys.EvalMultFinal) == 0 || len(req.EvalKeys.EvalSumFinal) == 0 {
		return nil, fmt.Errorf("final eval-mult and eval-sum keys are required")
	}
	packageBytes := req.PackageBytes
	if packageBytes <= 0 {
		return nil, fmt.Errorf("packageBytes must be positive")
	}
	payloadSlots := req.PayloadSlotCount
	if payloadSlots <= 0 {
		return nil, fmt.Errorf("payloadSlotCount must be positive")
	}
	candidateBlob := make([]byte, 0)
	candidateLens := make([]C.size_t, n)
	for i, ct := range req.CandidateCiphertexts {
		if len(ct) == 0 {
			return nil, fmt.Errorf("candidate ciphertext %d is empty", i)
		}
		candidateLens[i] = C.size_t(len(ct))
		candidateBlob = append(candidateBlob, ct...)
	}
	latQ := intsToCInts(req.CandidateLatQ)
	lonQ := intsToCInts(req.CandidateLonQ)
	brownies := intsToCInts(req.CandidateBrownies)
	packages, err := flattenCandidatePackages(req.CandidatePackages, packageBytes)
	if err != nil {
		return nil, err
	}
	comparator := C.CString(defaultStringGo(req.Comparator, "tanh_chebyshev"))
	defer C.free(unsafe.Pointer(comparator))
	schedule := C.CString(defaultStringGo(req.SelectorSchedule, "none"))
	defer C.free(unsafe.Pointer(schedule))

	minimalFlag := C.int(0)
	if req.MinimalRotationKeys {
		minimalFlag = 1
	}

	var out *C.uint8_t
	var outLen C.size_t
	var errBuf [512]C.char
	if rc := C.ARESFullFusePayloadCKKS(
		nil, // ctx_handle: NULL = create fresh context
		C.uint32_t(params.RingDim),
		C.double(params.ScalingFactor),
		C.uint32_t(params.Depth),
		(*C.uint8_t)(unsafe.Pointer(&req.InitiatorCiphertext[0])),
		C.size_t(len(req.InitiatorCiphertext)),
		(*C.uint8_t)(unsafe.Pointer(&candidateBlob[0])),
		(*C.size_t)(unsafe.Pointer(&candidateLens[0])),
		(*C.int)(unsafe.Pointer(&latQ[0])),
		(*C.int)(unsafe.Pointer(&lonQ[0])),
		(*C.int)(unsafe.Pointer(&brownies[0])),
		C.int(n),
		C.int(req.ProfileDim),
		C.int(req.InitiatorLatQ),
		C.int(req.InitiatorLonQ),
		C.double(req.Alpha),
		C.double(req.Beta),
		C.double(req.Gamma),
		comparator,
		C.int(req.ComparatorDegree),
		C.double(req.ComparatorGain),
		C.double(req.ComparatorScale),
		C.double(req.ComparatorBound),
		schedule,
		(*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalMultFinal[0])),
		C.size_t(len(req.EvalKeys.EvalMultFinal)),
		(*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalSumFinal[0])),
		C.size_t(len(req.EvalKeys.EvalSumFinal)),
		(*C.int)(unsafe.Pointer(&packages[0])),
		C.int(packageBytes),
		C.int(payloadSlots),
		minimalFlag,
		&out,
		&outLen,
		&errBuf[0],
		C.size_t(len(errBuf)),
	); rc != 0 {
		return nil, fmt.Errorf("openfhe full payload fusion failed: %s", C.GoString(&errBuf[0]))
	}
	defer C.free(unsafe.Pointer(out))
	return copyCBytes(out, outLen), nil
}

// EvalAddCKKSForContract returns ctA + ctB slot-wise. Pure addition
// does not require an eval-mult key.
func EvalAddCKKSForContract(params ContractParams, ctA, ctB []byte) ([]byte, error) {
	return evalBinaryCKKS(params, nil, ctA, ctB, "EvalAdd")
}

// EvalSubCKKSForContract returns ctA - ctB slot-wise.
func EvalSubCKKSForContract(params ContractParams, ctA, ctB []byte) ([]byte, error) {
	return evalBinaryCKKS(params, nil, ctA, ctB, "EvalSub")
}

// EvalMultCKKSForContract returns ctA × ctB slot-wise. Requires the
// joint eval-mult key (consumes one CKKS level).
func EvalMultCKKSForContract(params ContractParams, evalMultKey, ctA, ctB []byte) ([]byte, error) {
	if len(evalMultKey) == 0 {
		return nil, fmt.Errorf("eval-mult key is required")
	}
	return evalBinaryCKKS(params, evalMultKey, ctA, ctB, "EvalMult")
}

// EvalConstMultCKKSForContract multiplies a ciphertext by a cleartext
// scalar (does not consume a level).
func EvalConstMultCKKSForContract(params ContractParams, ct []byte, scalar float64) ([]byte, error) {
	if len(ct) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}
	cctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(cctx)

	ctH, err := deserializeCiphertext(cctx, ct)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(ctH)

	out := C.EvalMultConst(cctx, ctH, C.double(scalar))
	if out == nil {
		return nil, fmt.Errorf("eval-mult-const failed")
	}
	defer C.FreeCiphertext(out)
	return serializeCiphertext(out)
}

func evalBinaryCKKS(params ContractParams, evalMultKey, ctA, ctB []byte, op string) ([]byte, error) {
	if len(ctA) == 0 || len(ctB) == 0 {
		return nil, fmt.Errorf("%s: both ciphertexts are required", op)
	}
	cctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(cctx)

	if len(evalMultKey) > 0 {
		multKey, err := deserializeEvalMultKey(cctx, evalMultKey)
		if err != nil {
			return nil, err
		}
		defer C.FreeEvalMultKey(multKey)
		if rc := C.InsertEvalMultKey(cctx, multKey); rc != 0 {
			return nil, fmt.Errorf("%s: insert eval-mult key failed", op)
		}
	}

	a, err := deserializeCiphertext(cctx, ctA)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(a)
	b, err := deserializeCiphertext(cctx, ctB)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(b)

	var out C.CiphertextHandle
	switch op {
	case "EvalAdd":
		out = C.EvalAdd(cctx, a, b)
	case "EvalSub":
		out = C.EvalSub(cctx, a, b)
	case "EvalMult":
		out = C.EvalMult(cctx, a, b)
	default:
		return nil, fmt.Errorf("evalBinaryCKKS: unknown op %q", op)
	}
	if out == nil {
		return nil, fmt.Errorf("%s failed", op)
	}
	defer C.FreeCiphertext(out)
	return serializeCiphertext(out)
}

// EvalArgmaxCKKSForContract returns N "mask" ciphertexts where the
// argmax candidate's mask is ≈1 and losers' masks are ≈0. The
// caller supplies the sharpening polynomial whose coefficients
// approximate a step function on [-1, 1].
//
// Implementation: for each ordered pair (i, j), the helper computes
// sharpen(cts[i] - cts[j]). The product of sharpened differences
// across j != i gives mask[i]. Depth budget required ≈ log2(N) +
// depth(sharpening) — fits comfortably under depth=30 for N ≤ 16
// and degree-9 sharpening.
func EvalArgmaxCKKSForContract(
	params ContractParams,
	evalMultKey []byte,
	ciphertexts [][]byte,
	sharpCoeffs []float64,
) ([][]byte, error) {
	if len(ciphertexts) < 2 {
		return nil, fmt.Errorf("argmax needs at least 2 candidates, got %d", len(ciphertexts))
	}
	if len(evalMultKey) == 0 {
		return nil, fmt.Errorf("eval-mult key is required")
	}
	if len(sharpCoeffs) < 2 {
		return nil, fmt.Errorf("sharpening polynomial must have at least 2 coefficients")
	}
	cctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(cctx)

	multKey, err := deserializeEvalMultKey(cctx, evalMultKey)
	if err != nil {
		return nil, err
	}
	defer C.FreeEvalMultKey(multKey)
	if rc := C.InsertEvalMultKey(cctx, multKey); rc != 0 {
		return nil, fmt.Errorf("insert eval-mult key failed")
	}

	handles := make([]C.CiphertextHandle, len(ciphertexts))
	freeAll := func() {
		for _, h := range handles {
			if h != nil {
				C.FreeCiphertext(h)
			}
		}
	}
	defer freeAll()
	for i, raw := range ciphertexts {
		h, err := deserializeCiphertext(cctx, raw)
		if err != nil {
			return nil, fmt.Errorf("ciphertext[%d]: %w", i, err)
		}
		handles[i] = h
	}

	outHandles := make([]C.CiphertextHandle, len(ciphertexts))
	rc := C.EvalArgmax(
		cctx,
		(*C.CiphertextHandle)(unsafe.Pointer(&handles[0])),
		C.int(len(handles)),
		(*C.double)(unsafe.Pointer(&sharpCoeffs[0])),
		C.int(len(sharpCoeffs)),
		(*C.CiphertextHandle)(unsafe.Pointer(&outHandles[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("eval argmax failed (rc=%d)", int(rc))
	}
	defer func() {
		for _, h := range outHandles {
			if h != nil {
				C.FreeCiphertext(h)
			}
		}
	}()

	out := make([][]byte, len(outHandles))
	for i, h := range outHandles {
		raw, err := serializeCiphertext(h)
		if err != nil {
			return nil, fmt.Errorf("serialize mask[%d]: %w", i, err)
		}
		out[i] = raw
	}
	return out, nil
}

// EvalPolyCKKSForContract evaluates a polynomial p(x) = Σ coeffs[i]·xⁱ
// slot-wise on a ciphertext. coefficients is in ascending order
// (coefficients[0] is the constant term). evalMultKey is the joint
// eval-mult key from the keygen rounds; required for any polynomial
// with degree ≥ 2.
func EvalPolyCKKSForContract(
	params ContractParams,
	evalMultKey []byte,
	ciphertext []byte,
	coefficients []float64,
) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}
	if len(coefficients) == 0 {
		return nil, fmt.Errorf("coefficients are required")
	}
	if len(evalMultKey) == 0 && hasNonConstantTerm(coefficients) {
		return nil, fmt.Errorf("eval-mult key is required for non-constant polynomials")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	if len(evalMultKey) > 0 {
		multKey, err := deserializeEvalMultKey(ctx, evalMultKey)
		if err != nil {
			return nil, err
		}
		defer C.FreeEvalMultKey(multKey)
		if rc := C.InsertEvalMultKey(ctx, multKey); rc != 0 {
			return nil, fmt.Errorf("insert eval-mult key failed")
		}
	}

	ct, err := deserializeCiphertext(ctx, ciphertext)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(ct)

	out := C.EvalPolynomial(
		ctx, ct,
		(*C.double)(unsafe.Pointer(&coefficients[0])),
		C.int(len(coefficients)),
	)
	if out == nil {
		return nil, fmt.Errorf("eval poly failed")
	}
	defer C.FreeCiphertext(out)
	return serializeCiphertext(out)
}

func hasNonConstantTerm(coeffs []float64) bool {
	for i := 1; i < len(coeffs); i++ {
		if coeffs[i] != 0 {
			return true
		}
	}
	return false
}

// RoundTripCiphertext deserializes ct under the given parameters
// and immediately re-serializes the resulting CKKS Ciphertext
// object. Used by the SC-10 serialization golden test to detect
// OpenFHE version-drift that would break SC-10 lineage interop
// across deployments.
//
// Under a stable OpenFHE version, the returned bytes must be
// byte-identical to ct.
func RoundTripCiphertext(params ContractParams, ct []byte) ([]byte, error) {
	if len(ct) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}
	cctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(cctx)

	ctH, err := deserializeCiphertext(cctx, ct)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(ctH)

	return serializeCiphertext(ctH)
}

func EncryptCKKSForContract(params ContractParams, jointPublicKey []byte, values []float64) ([]byte, error) {
	if len(jointPublicKey) == 0 {
		return nil, fmt.Errorf("joint public key is required")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("values are required")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	pk, err := deserializePublicKey(ctx, jointPublicKey)
	if err != nil {
		return nil, err
	}
	defer C.FreePublicKey(pk)

	ct := C.Encrypt(ctx, pk, (*C.double)(unsafe.Pointer(&values[0])), C.int(len(values)))
	if ct == nil {
		return nil, fmt.Errorf("contract encryption failed")
	}
	defer C.FreeCiphertext(ct)
	return serializeCiphertext(ct)
}

func EncryptBFVForContract(params BFVContractParams, jointPublicKey []byte, values []int64) ([]byte, error) {
	if len(jointPublicKey) == 0 {
		return nil, fmt.Errorf("joint public key is required")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("values are required")
	}
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	pk, err := deserializePublicKey(ctx, jointPublicKey)
	if err != nil {
		return nil, err
	}
	defer C.FreePublicKey(pk)

	ct := C.EncryptPackedInt(ctx, pk, (*C.int64_t)(unsafe.Pointer(&values[0])), C.int(len(values)))
	if ct == nil {
		return nil, fmt.Errorf("BFV contract encryption failed")
	}
	defer C.FreeCiphertext(ct)
	return serializeCiphertext(ct)
}

func PartialDecryptCKKSForContract(params ContractParams, ciphertext []byte, secretKeyShare []byte, lead bool) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}
	if len(secretKeyShare) == 0 {
		return nil, fmt.Errorf("secret key share is required")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	ct, err := deserializeCiphertext(ctx, ciphertext)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(ct)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, lead)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)

	var partial C.CiphertextHandle
	if rc := C.MultiDecMain(ctx, ct, sk, &partial); rc != 0 {
		return nil, fmt.Errorf("contract partial decrypt failed")
	}
	defer C.FreeCiphertext(partial)
	return serializeCiphertext(partial)
}

func PartialDecryptBFVForContract(params BFVContractParams, ciphertext []byte, secretKeyShare []byte, lead bool) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}
	if len(secretKeyShare) == 0 {
		return nil, fmt.Errorf("secret key share is required")
	}
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	ct, err := deserializeCiphertext(ctx, ciphertext)
	if err != nil {
		return nil, err
	}
	defer C.FreeCiphertext(ct)

	sk, err := deserializeSecretKeyShare(ctx, secretKeyShare, lead)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)

	var partial C.CiphertextHandle
	if rc := C.MultiDecMain(ctx, ct, sk, &partial); rc != 0 {
		return nil, fmt.Errorf("BFV contract partial decrypt failed")
	}
	defer C.FreeCiphertext(partial)
	return serializeCiphertext(partial)
}

func FuseCKKSPartialsForContract(params ContractParams, partials [][]byte, nSlots int) ([]float64, error) {
	if len(partials) == 0 {
		return nil, fmt.Errorf("at least one partial decrypt share is required")
	}
	if nSlots <= 0 {
		return nil, fmt.Errorf("nSlots must be positive")
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	handles := make([]C.CiphertextHandle, len(partials))
	for i, raw := range partials {
		ct, err := deserializeCiphertext(ctx, raw)
		if err != nil {
			for _, h := range handles {
				if h != nil {
					C.FreeCiphertext(h)
				}
			}
			return nil, fmt.Errorf("deserialize partial %d: %w", i, err)
		}
		handles[i] = ct
	}
	defer func() {
		for _, h := range handles {
			if h != nil {
				C.FreeCiphertext(h)
			}
		}
	}()

	out := make([]C.double, nSlots)
	outN := C.int(len(out))
	if rc := C.MultiDecFusion(ctx, (*C.CiphertextHandle)(unsafe.Pointer(&handles[0])), C.int(len(handles)), (*C.double)(unsafe.Pointer(&out[0])), &outN); rc != 0 {
		return nil, fmt.Errorf("contract partial fusion failed")
	}
	values := make([]float64, int(outN))
	for i := range values {
		values[i] = float64(out[i])
	}
	return values, nil
}

func FuseBFVPartialsForContract(params BFVContractParams, partials [][]byte, nSlots int) ([]int64, error) {
	if len(partials) == 0 {
		return nil, fmt.Errorf("at least one partial decrypt share is required")
	}
	if nSlots <= 0 {
		return nil, fmt.Errorf("nSlots must be positive")
	}
	ctx, err := createBFVContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	handles := make([]C.CiphertextHandle, len(partials))
	for i, raw := range partials {
		ct, err := deserializeCiphertext(ctx, raw)
		if err != nil {
			for _, h := range handles {
				if h != nil {
					C.FreeCiphertext(h)
				}
			}
			return nil, fmt.Errorf("deserialize BFV partial %d: %w", i, err)
		}
		handles[i] = ct
	}
	defer func() {
		for _, h := range handles {
			if h != nil {
				C.FreeCiphertext(h)
			}
		}
	}()

	out := make([]C.int64_t, nSlots)
	outN := C.int(len(out))
	if rc := C.MultiDecFusionPackedInt(ctx, (*C.CiphertextHandle)(unsafe.Pointer(&handles[0])), C.int(len(handles)), (*C.int64_t)(unsafe.Pointer(&out[0])), &outN); rc != 0 {
		return nil, fmt.Errorf("BFV contract partial fusion failed")
	}
	values := make([]int64, int(outN))
	for i := range values {
		values[i] = int64(out[i])
	}
	return values, nil
}

func SmokeCKKS() error {
	var errBuf [512]C.char
	if rc := C.ARESOpenFHESmoke(&errBuf[0], C.size_t(len(errBuf))); rc != 0 {
		return fmt.Errorf("openfhe smoke failed: %s", C.GoString(&errBuf[0]))
	}
	return nil
}

func createContractContext(params ContractParams) (C.CryptoContextHandle, error) {
	if params.RingDim == 0 {
		params.RingDim = 1024
	}
	if params.ScalingFactor == 0 {
		params.ScalingFactor = float64(uint64(1) << 50)
	}
	if params.Depth == 0 {
		params.Depth = 30
	}
	// Compute batch_size from profile/payload needs when minimal keys are used,
	// so that eval-key and scoring contexts have matching batch_size. Default 0
	// keeps the legacy ring_dim/2 behavior.
	bs := C.uint32_t(0)
	if params.MinimalRotationKeys && params.ProfileDim > 0 && params.PayloadSlotCount > 0 {
		need := params.ProfileDim
		if params.PayloadSlotCount > need {
			need = params.PayloadSlotCount
		}
		bs = C.uint32_t(1)
		for bs < C.uint32_t(need) {
			bs <<= 1
		}
	} else if params.EvalSumOnlyRotationKeys && params.ProfileDim > 0 {
		// Chunked fusion: batch = next_pow2(profile_dim) so EvalSumKeyGen emits the
		// profile_dim fold set (replicating across the batch), no broadcast keys.
		bs = C.uint32_t(1)
		for bs < C.uint32_t(params.ProfileDim) {
			bs <<= 1
		}
	}
	ctx := C.CreateCKKSContext(C.uint32_t(params.RingDim), C.double(params.ScalingFactor), C.uint32_t(params.Depth), bs)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create OpenFHE contract context")
	}
	if params.MinimalRotationKeys {
		C.SetMinimalRotationKeys(ctx, C.int(params.ProfileDim), C.int(params.PayloadSlotCount))
	} else if params.EvalSumOnlyRotationKeys {
		C.SetEvalSumOnlyRotationKeys(ctx, C.int(params.ProfileDim))
	}
	return ctx, nil
}

func createBFVContractContext(params BFVContractParams) (C.CryptoContextHandle, error) {
	if params.RingDim == 0 {
		params.RingDim = 32768
	}
	if params.MultiplicativeDepth == 0 {
		params.MultiplicativeDepth = 20
	}
	if params.PlaintextModulus == 0 {
		params.PlaintextModulus = 65537
	}
	if params.BatchSize <= 0 {
		params.BatchSize = int(params.RingDim / 2)
	}
	ctx := C.CreateBFVContext(
		C.uint32_t(params.RingDim),
		C.uint32_t(params.MultiplicativeDepth),
		C.uint64_t(params.PlaintextModulus),
		C.uint32_t(params.BatchSize),
	)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create OpenFHE BFV contract context")
	}
	return ctx, nil
}

func serializePublicKey(pk C.PublicKeyHandle) ([]byte, error) {
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializePublicKey(pk, &data, &n); rc != 0 {
		return nil, fmt.Errorf("public-key serialization failed")
	}
	defer C.free(unsafe.Pointer(data))
	return copyCBytes(data, n), nil
}

func serializeSecretKeyShare(sk C.SecretKeyShareHandle) ([]byte, error) {
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializeSecretKeyShare(sk, &data, &n); rc != 0 {
		return nil, fmt.Errorf("secret-key share serialization failed")
	}
	defer C.free(unsafe.Pointer(data))
	return copyCBytes(data, n), nil
}

func serializeEvalMultKey(key C.EvalMultKeyHandle) ([]byte, error) {
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializeEvalMultKey(key, &data, &n); rc != 0 {
		return nil, fmt.Errorf("eval-mult key serialization failed")
	}
	defer C.free(unsafe.Pointer(data))
	return copyCBytes(data, n), nil
}

func serializeRotKey(key C.RotKeyHandle) ([]byte, error) {
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializeRotKey(key, &data, &n); rc != 0 {
		return nil, fmt.Errorf("eval-sum key serialization failed")
	}
	defer C.free(unsafe.Pointer(data))
	return copyCBytes(data, n), nil
}

func serializeCiphertext(ct C.CiphertextHandle) ([]byte, error) {
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializeCiphertext(ct, &data, &n); rc != 0 {
		return nil, fmt.Errorf("ciphertext serialization failed")
	}
	defer C.free(unsafe.Pointer(data))
	return copyCBytes(data, n), nil
}

func deserializePublicKey(ctx C.CryptoContextHandle, raw []byte) (C.PublicKeyHandle, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("public key bytes are required")
	}
	pk := C.DeserializePublicKey(ctx, (*C.uint8_t)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
	if pk == nil {
		return nil, fmt.Errorf("public-key deserialization failed")
	}
	return pk, nil
}

func deserializeCiphertext(ctx C.CryptoContextHandle, raw []byte) (C.CiphertextHandle, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("ciphertext bytes are required")
	}
	ct := C.DeserializeCiphertext(ctx, (*C.uint8_t)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
	if ct == nil {
		return nil, fmt.Errorf("ciphertext deserialization failed")
	}
	return ct, nil
}

func deserializeSecretKeyShare(ctx C.CryptoContextHandle, raw []byte, lead bool) (C.SecretKeyShareHandle, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("secret key share bytes are required")
	}
	leadInt := C.int(0)
	if lead {
		leadInt = 1
	}
	sk := C.DeserializeSecretKeyShare(ctx, (*C.uint8_t)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)), leadInt)
	if sk == nil {
		return nil, fmt.Errorf("secret-key share deserialization failed")
	}
	return sk, nil
}

func deserializeEvalMultKey(ctx C.CryptoContextHandle, raw []byte) (C.EvalMultKeyHandle, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("eval-mult key bytes are required")
	}
	key := C.DeserializeEvalMultKey(ctx, (*C.uint8_t)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
	if key == nil {
		return nil, fmt.Errorf("eval-mult key deserialization failed")
	}
	return key, nil
}

func deserializeRotKey(ctx C.CryptoContextHandle, raw []byte) (C.RotKeyHandle, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("eval-sum key bytes are required")
	}
	key := C.DeserializeRotKey(ctx, (*C.uint8_t)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
	if key == nil {
		return nil, fmt.Errorf("eval-sum key deserialization failed")
	}
	return key, nil
}

func deserializePublicKeys(ctx C.CryptoContextHandle, raws [][]byte) ([]C.PublicKeyHandle, func(), error) {
	handles := make([]C.PublicKeyHandle, len(raws))
	free := func() {
		for _, handle := range handles {
			if handle != nil {
				C.FreePublicKey(handle)
			}
		}
	}
	for i, raw := range raws {
		handle, err := deserializePublicKey(ctx, raw)
		if err != nil {
			free()
			return nil, nil, fmt.Errorf("deserialize public key %d: %w", i, err)
		}
		handles[i] = handle
	}
	return handles, free, nil
}

func deserializeEvalMultKeys(ctx C.CryptoContextHandle, raws [][]byte) ([]C.EvalMultKeyHandle, func(), error) {
	handles := make([]C.EvalMultKeyHandle, len(raws))
	free := func() {
		for _, handle := range handles {
			if handle != nil {
				C.FreeEvalMultKey(handle)
			}
		}
	}
	for i, raw := range raws {
		handle, err := deserializeEvalMultKey(ctx, raw)
		if err != nil {
			free()
			return nil, nil, fmt.Errorf("deserialize eval-mult key %d: %w", i, err)
		}
		handles[i] = handle
	}
	return handles, free, nil
}

func deserializeRotKeys(ctx C.CryptoContextHandle, raws [][]byte) ([]C.RotKeyHandle, func(), error) {
	handles := make([]C.RotKeyHandle, len(raws))
	free := func() {
		for _, handle := range handles {
			if handle != nil {
				C.FreeRotKey(handle)
			}
		}
	}
	for i, raw := range raws {
		handle, err := deserializeRotKey(ctx, raw)
		if err != nil {
			free()
			return nil, nil, fmt.Errorf("deserialize eval-sum key %d: %w", i, err)
		}
		handles[i] = handle
	}
	return handles, free, nil
}

func intsToCInts(values []int) []C.int {
	out := make([]C.int, len(values))
	for i, value := range values {
		out[i] = C.int(value)
	}
	return out
}

func flattenCandidatePackages(packages [][]int, packageBytes int) ([]C.int, error) {
	out := make([]C.int, 0, len(packages)*packageBytes)
	for i, pkg := range packages {
		if len(pkg) != packageBytes {
			return nil, fmt.Errorf("candidate package %d length = %d, want %d", i, len(pkg), packageBytes)
		}
		for _, value := range pkg {
			if value < 0 || value > 255 {
				return nil, fmt.Errorf("candidate package %d contains byte out of range", i)
			}
			out = append(out, C.int(value))
		}
	}
	return out, nil
}

func defaultStringGo(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func copyCBytes(data *C.uint8_t, n C.size_t) []byte {
	if data == nil || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(n))
}

func ThresholdSmokeCKKS(parties int) error {
	if parties < 2 {
		return fmt.Errorf("threshold smoke requires at least two parties")
	}
	ctx := C.CreateCKKSContext(C.uint32_t(1024), C.double(float64(uint64(1)<<50)), C.uint32_t(4), 0)
	if ctx == nil {
		return fmt.Errorf("failed to create OpenFHE threshold context")
	}
	defer C.FreeCryptoContext(ctx)

	pks := make([]C.PublicKeyHandle, parties)
	sks := make([]C.SecretKeyShareHandle, parties)
	if rc := C.KeyGenFirst(ctx, &pks[0], &sks[0]); rc != 0 {
		return fmt.Errorf("threshold first keygen failed")
	}
	defer C.FreePublicKey(pks[0])
	defer C.FreeSecretKeyShare(sks[0])
	for i := 1; i < parties; i++ {
		if rc := C.KeyGenNext(ctx, pks[i-1], &pks[i], &sks[i]); rc != 0 {
			return fmt.Errorf("threshold keygen party %d failed", i)
		}
		defer C.FreePublicKey(pks[i])
		defer C.FreeSecretKeyShare(sks[i])
	}

	for i := 0; i < parties; i++ {
		var multShare C.EvalMultKeyHandle
		if rc := C.GenEvalMultKeyShare(ctx, sks[i], &multShare); rc != 0 {
			return fmt.Errorf("threshold eval-mult share party %d failed", i)
		}
		defer C.FreeEvalMultKey(multShare)
		var rotShare C.RotKeyHandle
		if rc := C.GenRotKeyShare(ctx, sks[i], &rotShare); rc != 0 {
			return fmt.Errorf("threshold rotation/eval-sum share party %d failed", i)
		}
		defer C.FreeRotKey(rotShare)
	}

	var pkData *C.uint8_t
	var pkLen C.size_t
	if rc := C.SerializePublicKey(pks[parties-1], &pkData, &pkLen); rc != 0 {
		return fmt.Errorf("joint public-key serialization failed")
	}
	defer C.free(unsafe.Pointer(pkData))
	pkRoundTrip := C.DeserializePublicKey(ctx, pkData, pkLen)
	if pkRoundTrip == nil {
		return fmt.Errorf("joint public-key deserialization failed")
	}
	defer C.FreePublicKey(pkRoundTrip)

	values := []C.double{1.25, -2.5, 3.0, 0.5}
	ct := C.Encrypt(ctx, pkRoundTrip, (*C.double)(unsafe.Pointer(&values[0])), C.int(len(values)))
	if ct == nil {
		return fmt.Errorf("threshold encrypt failed")
	}
	defer C.FreeCiphertext(ct)

	var ctData *C.uint8_t
	var ctLen C.size_t
	if rc := C.SerializeCiphertext(ct, &ctData, &ctLen); rc != 0 {
		return fmt.Errorf("ciphertext serialization failed")
	}
	defer C.free(unsafe.Pointer(ctData))
	ctRoundTrip := C.DeserializeCiphertext(ctx, ctData, ctLen)
	if ctRoundTrip == nil {
		return fmt.Errorf("ciphertext deserialization failed")
	}
	defer C.FreeCiphertext(ctRoundTrip)

	doubled := C.EvalAdd(ctx, ctRoundTrip, ctRoundTrip)
	if doubled == nil {
		return fmt.Errorf("threshold eval-add failed")
	}
	defer C.FreeCiphertext(doubled)
	restored := C.EvalMultConst(ctx, doubled, C.double(0.5))
	if restored == nil {
		return fmt.Errorf("threshold eval-mult-const failed")
	}
	defer C.FreeCiphertext(restored)
	squared := C.EvalMult(ctx, restored, restored)
	if squared == nil {
		return fmt.Errorf("threshold eval-mult failed")
	}
	defer C.FreeCiphertext(squared)
	summed := C.EvalSum(ctx, squared, C.int(len(values)))
	if summed == nil {
		return fmt.Errorf("threshold eval-sum failed")
	}
	defer C.FreeCiphertext(summed)

	partials := make([]C.CiphertextHandle, parties)
	for i := 0; i < parties; i++ {
		if rc := C.MultiDecMain(ctx, summed, sks[i], &partials[i]); rc != 0 {
			return fmt.Errorf("threshold partial decrypt party %d failed", i)
		}
		defer C.FreeCiphertext(partials[i])
	}
	out := make([]C.double, 8)
	outN := C.int(len(out))
	if rc := C.MultiDecFusion(ctx, (*C.CiphertextHandle)(unsafe.Pointer(&partials[0])), C.int(parties), (*C.double)(unsafe.Pointer(&out[0])), &outN); rc != 0 {
		return fmt.Errorf("threshold decrypt fusion failed")
	}
	if outN == 0 {
		return fmt.Errorf("threshold decrypt fusion returned no slots")
	}
	const want = 17.0625
	got := float64(out[0])
	if math.Abs(got-want) > 0.05 {
		return fmt.Errorf("threshold fused value mismatch: got %.6f want %.6f", got, want)
	}
	return nil
}

func ScoreCandidatesCKKS(req ScoreRequest) (ScoreResult, error) {
	nCandidates := len(req.CandidateProfiles)
	if len(req.InitiatorProfile) == 0 {
		return ScoreResult{}, fmt.Errorf("initiator profile is required")
	}
	if nCandidates == 0 {
		return ScoreResult{}, fmt.Errorf("at least one candidate is required")
	}
	dim := len(req.InitiatorProfile)
	flatProfiles := make([]float64, 0, nCandidates*dim)
	for i, profile := range req.CandidateProfiles {
		if len(profile) != dim {
			return ScoreResult{}, fmt.Errorf("candidate %d profile dim=%d want %d", i, len(profile), dim)
		}
		flatProfiles = append(flatProfiles, profile...)
	}
	if len(req.CandidateLatQ) != nCandidates || len(req.CandidateLonQ) != nCandidates || len(req.CandidateBrownies) != nCandidates {
		return ScoreResult{}, fmt.Errorf("candidate coordinate/brownie arrays must match candidate count")
	}
	if len(req.CandidatePackages) != nCandidates {
		return ScoreResult{}, fmt.Errorf("candidate package array must match candidate count")
	}
	packageBytes := len(req.CandidatePackages[0])
	if packageBytes == 0 {
		return ScoreResult{}, fmt.Errorf("candidate packages are required for native payload fusion")
	}
	payloadSlotCount := req.PayloadSlotCount
	if payloadSlotCount == 0 {
		payloadSlotCount = packageBytes * 8
	}
	if payloadSlotCount < packageBytes*8 {
		return ScoreResult{}, fmt.Errorf("payload slot count %d cannot hold %d package bits", payloadSlotCount, packageBytes*8)
	}
	flatPackages := make([]int, 0, nCandidates*packageBytes)
	for i, pkg := range req.CandidatePackages {
		if len(pkg) != packageBytes {
			return ScoreResult{}, fmt.Errorf("candidate %d package length=%d want %d", i, len(pkg), packageBytes)
		}
		for j, value := range pkg {
			if value < 0 || value > 255 {
				return ScoreResult{}, fmt.Errorf("candidate %d package byte %d out of range: %d", i, j, value)
			}
			flatPackages = append(flatPackages, value)
		}
	}

	cLat := intsToC(req.CandidateLatQ)
	cLon := intsToC(req.CandidateLonQ)
	cBrownie := intsToC(req.CandidateBrownies)
	cPackages := intsToC(flatPackages)
	scores := make([]float64, nCandidates)
	maskValues := make([]float64, nCandidates)
	payloadValues := make([]float64, payloadSlotCount)
	var winnerIndex C.int
	var winnerScore C.double
	var errBuf [1024]C.char
	distanceFunction := C.CString(req.DistanceFunction)
	defer C.free(unsafe.Pointer(distanceFunction))
	comparator := C.CString(req.Comparator)
	defer C.free(unsafe.Pointer(comparator))
	maskMode := C.CString(req.MaskMode)
	defer C.free(unsafe.Pointer(maskMode))
	selectorSchedule := C.CString(req.SelectorSchedule)
	defer C.free(unsafe.Pointer(selectorSchedule))

	rc := C.ARESScoreCandidatesCKKS(
		(*C.double)(unsafe.Pointer(&req.InitiatorProfile[0])),
		C.int(dim),
		C.int(req.InitiatorLatQ),
		C.int(req.InitiatorLonQ),
		(*C.double)(unsafe.Pointer(&flatProfiles[0])),
		(*C.int)(unsafe.Pointer(&cLat[0])),
		(*C.int)(unsafe.Pointer(&cLon[0])),
		(*C.int)(unsafe.Pointer(&cBrownie[0])),
		C.int(nCandidates),
		C.double(req.Alpha),
		C.double(req.Beta),
		C.double(req.Gamma),
		distanceFunction,
		comparator,
		C.int(req.ComparatorDegree),
		C.double(req.ComparatorGain),
		C.double(req.ComparatorScale),
		C.double(req.ComparatorBound),
		maskMode,
		selectorSchedule,
		C.int(req.ScalingModSize),
		C.int(req.FirstModSize),
		(*C.int)(unsafe.Pointer(&cPackages[0])),
		C.int(packageBytes),
		C.int(payloadSlotCount),
		(*C.double)(unsafe.Pointer(&scores[0])),
		(*C.double)(unsafe.Pointer(&maskValues[0])),
		(*C.double)(unsafe.Pointer(&payloadValues[0])),
		&winnerIndex,
		&winnerScore,
		&errBuf[0],
		C.size_t(len(errBuf)),
	)
	if rc != 0 {
		return ScoreResult{}, fmt.Errorf("openfhe scoring failed: %s", C.GoString(&errBuf[0]))
	}
	return ScoreResult{
		Scores:        scores,
		MaskValues:    maskValues,
		PayloadValues: payloadValues,
		WinnerIndex:   int(winnerIndex),
		WinnerScore:   float64(winnerScore),
	}, nil
}

func intsToC(values []int) []C.int {
	out := make([]C.int, len(values))
	for i, value := range values {
		out[i] = C.int(value)
	}
	return out
}

// OpenFHEVersion returns the OpenFHE library version string linked
// into this binary (e.g. "v1.5.1"). Used by helper subprocesses to
// surface version mismatches at startup.
func OpenFHEVersion() string {
	var buf [32]C.char
	n := C.GetOpenFHEVersion(&buf[0], C.int(len(buf)))
	if n <= 0 {
		return "unknown"
	}
	return C.GoStringN(&buf[0], n)
}

// SchemeSwitchingArgmin runs the depth-independent CKKS→FHEW scheme-switching
// argmin over a single packed ciphertext containing numValues keys in slots
// 0..numValues-1. Returns [minCiphertext, argminCiphertext] where argmin is a
// one-hot encoding over numValues slots. Single-key only (initiator holds sk).
// scaleSign defaults to 1.0 when <= 0. numValues must be a power of two >= 2.
func SchemeSwitchingArgmin(
	ctx C.CryptoContextHandle,
	pk C.PublicKeyHandle,
	sk C.SecretKeyShareHandle,
	packedCt C.CiphertextHandle,
	numValues uint32,
	scaleSign float64,
) (minCt, argminCt C.CiphertextHandle, err error) {
	var errBuf [1024]C.char
	var outMin, outArgmin C.CiphertextHandle
	rc := C.SchemeSwitchingArgmin(ctx, pk, sk, packedCt,
		C.uint32_t(numValues), C.double(scaleSign),
		&outMin, &outArgmin, &errBuf[0], C.size_t(len(errBuf)))
	if rc != 0 {
		return nil, nil, fmt.Errorf("scheme-switching argmin: %s", C.GoString(&errBuf[0]))
	}
	return outMin, outArgmin, nil
}

// SingleKeySoftArgmin exercises the single-key soft-mask argmin at ring 2^14
// with n scores. Single-party keygen, encrypts n scores, runs EvalArgmax
// (degree-3 polynomial product-tree argmin), decrypts masks with DecryptSingle
// (clean, no threshold fusion). Returns mask values and winner index.
func SingleKeySoftArgmin(scores []float64, degree int) ([]float64, int, error) {
	n := len(scores)
	if n < 2 {
		return nil, -1, fmt.Errorf("need >=2 scores")
	}
	params := ContractParams{
		RingDim:       1 << 14,
		ScalingFactor: float64(uint64(1) << 50),
		Depth:         4,
	}
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, -1, err
	}
	defer C.FreeCryptoContext(ctx)

	var pk C.PublicKeyHandle
	var sk C.SecretKeyShareHandle
	if C.KeyGenFirst(ctx, &pk, &sk) != 0 {
		return nil, -1, fmt.Errorf("keygen failed")
	}
	defer C.FreePublicKey(pk)
	defer C.FreeSecretKeyShare(sk)

	// Single-party: generate eval-mult key (threshold keygen does this in round)
	if C.SingleKeyEvalMultKeyGen(ctx, sk) != 0 {
		return nil, -1, fmt.Errorf("eval-mult keygen failed")
	}

	cts := make([]C.CiphertextHandle, n)
	for i := 0; i < n; i++ {
		score := make([]C.double, 4)
		score[0] = C.double(scores[i])
		cts[i] = C.Encrypt(ctx, pk, &score[0], 4)
		if cts[i] == nil {
			return nil, -1, fmt.Errorf("encrypt[%d] failed", i)
		}
	}
	defer func() {
		for _, ct := range cts {
			C.FreeCiphertext(ct)
		}
	}()

	sharp := []C.double{0.5, 0.75, 0, -0.25}
	if degree == 1 {
		sharp = []C.double{0.5, 0.5}
	}
	masks := make([]C.CiphertextHandle, n)
	rc := C.EvalArgmax(ctx, &cts[0], C.int(n), &sharp[0], C.int(len(sharp)), &masks[0])
	if rc != 0 {
		return nil, -1, fmt.Errorf("argmax failed (depth %d insufficient for n=%d)", params.Depth, n)
	}
	defer func() {
		for _, m := range masks {
			C.FreeCiphertext(m)
		}
	}()

	result := make([]float64, n)
	best, bestVal := -1, 0.0
	for i := 0; i < n; i++ {
		var outVal C.double
		outN := C.int(1)
		if C.DecryptSingle(ctx, masks[i], sk, &outVal, &outN) != 0 {
			return nil, -1, fmt.Errorf("decrypt mask[%d] failed", i)
		}
		result[i] = float64(outVal)
		if best < 0 || result[i] > bestVal {
			best, bestVal = i, result[i]
		}
	}
	return result, best, nil
}

// SingleKeyGen creates a single-party CKKS keypair (not threshold). Returns
// serialized public key and secret key. Generates eval-mult key on the context.
func SingleKeyGen(params ContractParams) (pk, sk []byte, err error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, nil, err
	}
	defer C.FreeCryptoContext(ctx)

	var cPk C.PublicKeyHandle
	var cSk C.SecretKeyShareHandle
	if C.KeyGenFirst(ctx, &cPk, &cSk) != 0 {
		return nil, nil, fmt.Errorf("keygen failed")
	}
	defer C.FreePublicKey(cPk)
	defer C.FreeSecretKeyShare(cSk)

	if C.SingleKeyEvalMultKeyGen(ctx, cSk) != 0 {
		return nil, nil, fmt.Errorf("eval-mult keygen failed")
	}

	pkBytes, err := serializePublicKey(cPk)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize pk: %w", err)
	}
	skBytes, err := serializeSecretKeyShare(cSk)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize sk: %w", err)
	}
	return pkBytes, skBytes, nil
}

// SingleKeyDecrypt decrypts a ciphertext with a single-party secret key
// (no threshold fusion). Returns the decrypted values.
func SingleKeyDecrypt(params ContractParams, sk, ct []byte, nSlots int) ([]float64, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	cSk, err := deserializeSecretKeyShare(ctx, sk, true)
	if err != nil {
		return nil, fmt.Errorf("deserialize sk: %w", err)
	}
	defer C.FreeSecretKeyShare(cSk)

	cCt, err := deserializeCiphertext(ctx, ct)
	if err != nil {
		return nil, fmt.Errorf("deserialize ct: %w", err)
	}
	defer C.FreeCiphertext(cCt)

	out := make([]C.double, nSlots)
	outN := C.int(nSlots)
	if C.DecryptSingle(ctx, cCt, cSk, &out[0], &outN) != 0 {
		return nil, fmt.Errorf("decrypt failed")
	}
	result := make([]float64, int(outN))
	for i := range result {
		result[i] = float64(out[i])
	}
	return result, nil
}

// AuctionWeights parameterises the lexicographic ranking key.
type AuctionWeights struct{ K, WStar, WDist float64 }

// SingleKeyAuctionServer runs the server-side reverse auction on encrypted bids.
// It takes only the rider's PUBLIC key (never the secret key). Returns serialized
// encrypted mask ciphertexts — the server CANNOT decrypt them. The rider calls
// SingleKeyAuctionDecrypt locally to learn the winner.
//
// Each driver's bid must be signed with their long-term identity key:
//
//	sig_i = Sign(sk_driver_i, H(enc_bid_i || nonce_i || session_id))
//
// The rider verifies the winning driver's signature after decryption.
// This prevents server-spawned ghost drivers from winning without detection.
func SingleKeyAuctionServer(
	params ContractParams,
	pk []byte,
	priceCents []int, starNorms, distSqs []float64,
	nonces [][]byte,
	floorCents, capCents int,
	w AuctionWeights,
	degree int,
) (encryptedMasks [][]byte, err error) {
	n := len(priceCents)
	if n < 2 {
		return nil, fmt.Errorf("need >= 2 bids, got %d", n)
	}
	if len(starNorms) != n || len(distSqs) != n || len(nonces) != n {
		return nil, fmt.Errorf("mismatched input lengths")
	}
	if pk == nil || len(pk) == 0 {
		return nil, fmt.Errorf("pk required")
	}

	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	cPk, err := deserializePublicKey(ctx, pk)
	if err != nil {
		return nil, fmt.Errorf("deserialize pk: %w", err)
	}
	defer C.FreePublicKey(cPk)

	span := float64(capCents - floorCents)
	if span <= 0 {
		span = 1
	}
	floor := float64(floorCents)
	Kc, wsc, wdc := C.double(w.K), C.double(w.WStar), C.double(w.WDist)

	maxKeySpan := w.K + w.WStar*5.0
	for _, d := range distSqs {
		if w.WDist*d > maxKeySpan {
			maxKeySpan = w.WDist * d
		}
	}
	scale := C.double(0.9 / maxKeySpan)

	scores := make([]C.CiphertextHandle, n)
	for i := 0; i < n; i++ {
		fullOffset := -scale * (wsc*C.double(5.0-starNorms[i]) + wdc*C.double(distSqs[i]) - Kc*C.double(floor)/C.double(span))
		offVals := make([]C.double, 4)
		offVals[0] = fullOffset
		offCt := C.Encrypt(ctx, cPk, &offVals[0], 4)
		if offCt == nil {
			return nil, fmt.Errorf("encrypt offset[%d] failed", i)
		}
		defer C.FreeCiphertext(offCt)

		pVals := make([]C.double, 4)
		pVals[0] = C.double(priceCents[i])
		pCt := C.Encrypt(ctx, cPk, &pVals[0], 4)
		if pCt == nil {
			return nil, fmt.Errorf("encrypt price[%d] failed", i)
		}
		defer C.FreeCiphertext(pCt)

		scaledPrice := C.EvalMultConst(ctx, pCt, -scale*Kc/C.double(span))
		if scaledPrice == nil {
			return nil, fmt.Errorf("scale price[%d] failed", i)
		}
		score := C.EvalAdd(ctx, scaledPrice, offCt)
		C.FreeCiphertext(scaledPrice)
		if score == nil {
			return nil, fmt.Errorf("assemble score[%d] failed", i)
		}
		defer C.FreeCiphertext(score)
		scores[i] = score
	}

	sharp := []C.double{0.5, 0.75, 0, -0.25}
	if degree == 1 {
		sharp = []C.double{0.5, 0.5}
	}
	cMasks := make([]C.CiphertextHandle, n)
	rc := C.EvalArgmax(ctx, &scores[0], C.int(n), &sharp[0], C.int(len(sharp)), &cMasks[0])
	if rc != 0 {
		return nil, fmt.Errorf("argmax failed (depth %d insufficient for n=%d)", params.Depth, n)
	}
	defer func() {
		for _, m := range cMasks {
			C.FreeCiphertext(m)
		}
	}()

	encryptedMasks = make([][]byte, n)
	for i := 0; i < n; i++ {
		encryptedMasks[i], err = serializeCiphertext(cMasks[i])
		if err != nil {
			return nil, fmt.Errorf("serialize mask[%d]: %w", i, err)
		}
	}
	return encryptedMasks, nil
}

// SingleKeyEncrypt encrypts a single scalar under a single-party public key,
// returning a serialized ciphertext (4-slot, value in slot 0). The caller
// uses this to encrypt a bid locally so the server never sees the plaintext.
func SingleKeyEncrypt(params ContractParams, pk []byte, value float64) ([]byte, error) {
	if len(pk) == 0 {
		return nil, fmt.Errorf("pk required")
	}

	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	cPk, err := deserializePublicKey(ctx, pk)
	if err != nil {
		return nil, fmt.Errorf("deserialize pk: %w", err)
	}
	defer C.FreePublicKey(cPk)

	vals := make([]C.double, 4)
	vals[0] = C.double(value)
	ct := C.Encrypt(ctx, cPk, &vals[0], 4)
	if ct == nil {
		return nil, fmt.Errorf("encrypt failed")
	}
	defer C.FreeCiphertext(ct)

	return serializeCiphertext(ct)
}

// SingleKeyAuctionServerEnc is the privacy-preserving variant of
// SingleKeyAuctionServer. Instead of plaintext prices, it accepts
// pre-encrypted bid ciphertexts produced by each bidder via
// SingleKeyEncrypt. The server never learns plaintext prices; it only
// manipulates ciphertexts homomorphically.
//
// The server still encrypts the server-authoritative offset (rating / distance)
// because those values are server-visible by design. Only the price component
// is kept opaque through bidder-side encryption.
func SingleKeyAuctionServerEnc(
	params ContractParams,
	pk []byte,
	encBids [][]byte,
	starNorms, distSqs []float64,
	nonces [][]byte,
	floorCents, capCents int,
	w AuctionWeights,
	degree int,
) (encryptedMasks [][]byte, err error) {
	n := len(encBids)
	if n < 2 {
		return nil, fmt.Errorf("need >= 2 bids, got %d", n)
	}
	if len(starNorms) != n || len(distSqs) != n || len(nonces) != n {
		return nil, fmt.Errorf("mismatched input lengths")
	}
	if len(pk) == 0 {
		return nil, fmt.Errorf("pk required")
	}

	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	cPk, err := deserializePublicKey(ctx, pk)
	if err != nil {
		return nil, fmt.Errorf("deserialize pk: %w", err)
	}
	defer C.FreePublicKey(cPk)

	span := float64(capCents - floorCents)
	if span <= 0 {
		span = 1
	}
	floor := float64(floorCents)
	Kc, wsc, wdc := C.double(w.K), C.double(w.WStar), C.double(w.WDist)

	maxKeySpan := w.K + w.WStar*5.0
	for _, d := range distSqs {
		if w.WDist*d > maxKeySpan {
			maxKeySpan = w.WDist * d
		}
	}
	scale := C.double(0.9 / maxKeySpan)

	scores := make([]C.CiphertextHandle, n)
	for i := 0; i < n; i++ {
		fullOffset := -scale * (wsc*C.double(5.0-starNorms[i]) + wdc*C.double(distSqs[i]) - Kc*C.double(floor)/C.double(span))
		offVals := make([]C.double, 4)
		offVals[0] = fullOffset
		offCt := C.Encrypt(ctx, cPk, &offVals[0], 4)
		if offCt == nil {
			return nil, fmt.Errorf("encrypt offset[%d] failed", i)
		}
		defer C.FreeCiphertext(offCt)

		// Price comes in pre-encrypted from the bidder — deserialize it.
		pCt, err := deserializeCiphertext(ctx, encBids[i])
		if err != nil {
			return nil, fmt.Errorf("deserialize encBid[%d]: %w", i, err)
		}
		defer C.FreeCiphertext(pCt)

		scaledPrice := C.EvalMultConst(ctx, pCt, -scale*Kc/C.double(span))
		if scaledPrice == nil {
			return nil, fmt.Errorf("scale price[%d] failed", i)
		}
		score := C.EvalAdd(ctx, scaledPrice, offCt)
		C.FreeCiphertext(scaledPrice)
		if score == nil {
			return nil, fmt.Errorf("assemble score[%d] failed", i)
		}
		defer C.FreeCiphertext(score)
		scores[i] = score
	}

	sharp := []C.double{0.5, 0.75, 0, -0.25}
	if degree == 1 {
		sharp = []C.double{0.5, 0.5}
	}
	cMasks := make([]C.CiphertextHandle, n)
	rc := C.EvalArgmax(ctx, &scores[0], C.int(n), &sharp[0], C.int(len(sharp)), &cMasks[0])
	if rc != 0 {
		return nil, fmt.Errorf("argmax failed (depth %d insufficient for n=%d)", params.Depth, n)
	}
	defer func() {
		for _, m := range cMasks {
			C.FreeCiphertext(m)
		}
	}()

	encryptedMasks = make([][]byte, n)
	for i := 0; i < n; i++ {
		encryptedMasks[i], err = serializeCiphertext(cMasks[i])
		if err != nil {
			return nil, fmt.Errorf("serialize mask[%d]: %w", i, err)
		}
	}
	return encryptedMasks, nil
}

// SingleKeyAuctionDecrypt decrypts encrypted masks with the rider's secret key.
// Returns per-driver mask values and the winner index (argmax). The agreed price
// is the winner's lineage-committed bid — verified by checking the driver's
// signature on H(enc_bid || nonce || session_id).
func SingleKeyAuctionDecrypt(
	params ContractParams,
	sk []byte,
	encryptedMasks [][]byte,
) (masks []float64, winnerIdx int, err error) {
	n := len(encryptedMasks)
	if n < 2 {
		return nil, -1, fmt.Errorf("need >= 2 masks")
	}
	if sk == nil || len(sk) == 0 {
		return nil, -1, fmt.Errorf("sk required")
	}

	ctx, err := createContractContext(params)
	if err != nil {
		return nil, -1, err
	}
	defer C.FreeCryptoContext(ctx)

	cSk, err := deserializeSecretKeyShare(ctx, sk, true)
	if err != nil {
		return nil, -1, fmt.Errorf("deserialize sk: %w", err)
	}
	defer C.FreeSecretKeyShare(cSk)

	masks = make([]float64, n)
	best, bestVal := -1, 0.0
	for i := 0; i < n; i++ {
		cCt, err := deserializeCiphertext(ctx, encryptedMasks[i])
		if err != nil {
			return nil, -1, fmt.Errorf("deserialize mask[%d]: %w", i, err)
		}
		var v C.double
		nOut := C.int(1)
		if C.DecryptSingle(ctx, cCt, cSk, &v, &nOut) != 0 {
			C.FreeCiphertext(cCt)
			return nil, -1, fmt.Errorf("decrypt mask[%d] failed", i)
		}
		C.FreeCiphertext(cCt)
		masks[i] = float64(v)
		if best < 0 || masks[i] > bestVal {
			best, bestVal = i, masks[i]
		}
	}
	return masks, best, nil
}

// --- Shared context (context-reuse) variants -----------------------------------

// CryptoContext is a reusable CKKS context that callers can create once and pass
// to multiple WithContext functions, avoiding the per-call context
// allocation/deallocation overhead (~3 GB at ring 2^16). The caller MUST call
// Close() to free the underlying C handle.
type CryptoContext struct {
	handle C.CryptoContextHandle
}

// NewCryptoContext creates a CKKS context from ContractParams. The caller owns the
// returned context and must call Close() to free it.
func NewCryptoContext(params ContractParams) (*CryptoContext, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	return &CryptoContext{handle: ctx}, nil
}

// Close frees the underlying C CKKS context handle.
func (c *CryptoContext) Close() {
	if c.handle != nil {
		C.FreeCryptoContext(c.handle)
		c.handle = nil
	}
}

// evalKeyRound1LeadWithContext is the context-reusing body of EvalKeyRound1Lead.
func evalKeyRound1LeadWithContext(ctx *CryptoContext, secretKeyShare []byte) (EvalKeyRound1LeadShare, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, true)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)
	var mult C.EvalMultKeyHandle
	if rc := C.EvalMultKeyGenLead(ctx.handle, sk, &mult); rc != 0 {
		return EvalKeyRound1LeadShare{}, fmt.Errorf("eval-mult lead key generation failed")
	}
	defer C.FreeEvalMultKey(mult)
	multBytes, err := serializeEvalMultKey(mult)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	var sum C.RotKeyHandle
	if rc := C.EvalSumKeyGenLead(ctx.handle, sk, &sum); rc != 0 {
		return EvalKeyRound1LeadShare{}, fmt.Errorf("eval-sum lead key generation failed")
	}
	defer C.FreeRotKey(sum)
	sumBytes, err := serializeRotKey(sum)
	if err != nil {
		return EvalKeyRound1LeadShare{}, err
	}
	return EvalKeyRound1LeadShare{EvalMultBase: multBytes, EvalSumBase: sumBytes}, nil
}

// EvalKeyRound1LeadWithContext is like EvalKeyRound1Lead but uses the provided
// shared context instead of creating a new one.
func EvalKeyRound1LeadWithContext(ctx *CryptoContext, secretKeyShare []byte) (EvalKeyRound1LeadShare, error) {
	return evalKeyRound1LeadWithContext(ctx, secretKeyShare)
}

func EvalMultKeyGenLeadWithContext(ctx *CryptoContext, secretKeyShare []byte) ([]byte, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, true)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)
	var mult C.EvalMultKeyHandle
	if rc := C.EvalMultKeyGenLead(ctx.handle, sk, &mult); rc != 0 {
		return nil, fmt.Errorf("eval-mult lead key generation failed")
	}
	defer C.FreeEvalMultKey(mult)
	return serializeEvalMultKey(mult)
}

func EvalMultKeySwitchShareWithContext(ctx *CryptoContext, secretKeyShare, evalMultBase []byte) ([]byte, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, false)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)
	multBase, err := deserializeEvalMultKey(ctx.handle, evalMultBase)
	if err != nil {
		return nil, err
	}
	defer C.FreeEvalMultKey(multBase)
	var multShare C.EvalMultKeyHandle
	if rc := C.EvalMultKeySwitchShare(ctx.handle, sk, multBase, &multShare); rc != 0 {
		return nil, fmt.Errorf("eval-mult switch-share generation failed")
	}
	defer C.FreeEvalMultKey(multShare)
	return serializeEvalMultKey(multShare)
}

// EvalKeyRound1ParticipantWithContext is like EvalKeyRound1Participant but uses the
// provided shared context instead of creating a new one.
func EvalKeyRound1ParticipantWithContext(ctx *CryptoContext, secretKeyShare, evalMultBase, evalSumBase, ownPublicKey []byte) (EvalKeyRound1ParticipantShare, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, false)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)
	multBase, err := deserializeEvalMultKey(ctx.handle, evalMultBase)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeEvalMultKey(multBase)
	sumBase, err := deserializeRotKey(ctx.handle, evalSumBase)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreeRotKey(sumBase)
	ownPK, err := deserializePublicKey(ctx.handle, ownPublicKey)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	defer C.FreePublicKey(ownPK)
	var multShare C.EvalMultKeyHandle
	if rc := C.EvalMultKeySwitchShare(ctx.handle, sk, multBase, &multShare); rc != 0 {
		return EvalKeyRound1ParticipantShare{}, fmt.Errorf("eval-mult switch-share generation failed")
	}
	defer C.FreeEvalMultKey(multShare)
	multBytes, err := serializeEvalMultKey(multShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	var sumShare C.RotKeyHandle
	if rc := C.EvalSumKeyShare(ctx.handle, sk, sumBase, ownPK, &sumShare); rc != 0 {
		return EvalKeyRound1ParticipantShare{}, fmt.Errorf("eval-sum share generation failed")
	}
	defer C.FreeRotKey(sumShare)
	sumBytes, err := serializeRotKey(sumShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	return EvalKeyRound1ParticipantShare{EvalMultSwitchShare: multBytes, EvalSumShare: sumBytes}, nil
}

// CombineEvalMultSwitchSharesWithContext is like CombineEvalMultSwitchShares but
// uses the provided shared context.
func CombineEvalMultSwitchSharesWithContext(ctx *CryptoContext, publicKeys, evalMultShares [][]byte) ([]byte, error) {
	pks, freePKs, err := deserializePublicKeys(ctx.handle, publicKeys)
	if err != nil {
		return nil, err
	}
	defer freePKs()
	multShares, freeMultShares, err := deserializeEvalMultKeys(ctx.handle, evalMultShares)
	if err != nil {
		return nil, err
	}
	defer freeMultShares()
	var joined C.EvalMultKeyHandle
	if rc := C.CombineEvalMultSwitchShares(ctx.handle, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.EvalMultKeyHandle)(unsafe.Pointer(&multShares[0])), C.int(len(multShares)), &joined); rc != 0 {
		return nil, fmt.Errorf("eval-mult switch-share combination failed")
	}
	defer C.FreeEvalMultKey(joined)
	return serializeEvalMultKey(joined)
}

// NewEvalSumIncrementalFoldWithContext is like NewEvalSumIncrementalFold but uses
// the provided shared context. The returned fold does NOT own the context — the
// caller must keep ctx alive until Finalize() returns.
func NewEvalSumIncrementalFoldWithContext(ctx *CryptoContext, leadBase []byte) (*EvalSumIncrementalFold, error) {
	seed, err := deserializeRotKey(ctx.handle, leadBase)
	if err != nil {
		return nil, err
	}
	accum := C.EvalSumCombineStart(seed)
	C.FreeRotKey(seed)
	if accum == nil {
		return nil, fmt.Errorf("eval-sum combine start failed")
	}
	return &EvalSumIncrementalFold{ctx: ctx.handle, accum: accum, ownsCtx: false}, nil
}

// EvalKeyRound2ParticipantWithContext is like EvalKeyRound2Participant but uses
// the provided shared context.
func EvalKeyRound2ParticipantWithContext(ctx *CryptoContext, secretKeyShare, evalMultJoined, finalPublicKey []byte, lead bool) (EvalKeyRound2ParticipantShare, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, lead)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeSecretKeyShare(sk)
	joined, err := deserializeEvalMultKey(ctx.handle, evalMultJoined)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreeEvalMultKey(joined)
	finalPK, err := deserializePublicKey(ctx.handle, finalPublicKey)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	defer C.FreePublicKey(finalPK)
	var finalShare C.EvalMultKeyHandle
	if rc := C.EvalMultKeyFinalShare(ctx.handle, sk, joined, finalPK, &finalShare); rc != 0 {
		return EvalKeyRound2ParticipantShare{}, fmt.Errorf("eval-mult final-share generation failed")
	}
	defer C.FreeEvalMultKey(finalShare)
	finalBytes, err := serializeEvalMultKey(finalShare)
	if err != nil {
		return EvalKeyRound2ParticipantShare{}, err
	}
	return EvalKeyRound2ParticipantShare{EvalMultFinalShare: finalBytes}, nil
}

// CombineEvalKeyRound2WithContext is like CombineEvalKeyRound2 but uses the
// provided shared context.
func CombineEvalKeyRound2WithContext(ctx *CryptoContext, finalPublicKey []byte, evalMultFinalShares [][]byte, evalSumFinal []byte) (EvalKeyFinal, error) {
	finalPK, err := deserializePublicKey(ctx.handle, finalPublicKey)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer C.FreePublicKey(finalPK)
	finalShares := make([]C.EvalMultKeyHandle, len(evalMultFinalShares))
	for i, b := range evalMultFinalShares {
		finalShares[i], err = deserializeEvalMultKey(ctx.handle, b)
		if err != nil {
			for j := 0; j < i; j++ {
				C.FreeEvalMultKey(finalShares[j])
			}
			return EvalKeyFinal{}, err
		}
	}
	defer func() {
		for _, s := range finalShares {
			if s != nil {
				C.FreeEvalMultKey(s)
			}
		}
	}()
	sumFinal, err := deserializeRotKey(ctx.handle, evalSumFinal)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	defer C.FreeRotKey(sumFinal)
	var final C.EvalMultKeyHandle
	if rc := C.CombineEvalMultFinalShares(ctx.handle, finalPK, &finalShares[0], C.int(len(finalShares)), &final); rc != 0 {
		return EvalKeyFinal{}, fmt.Errorf("combine eval-mult final shares failed")
	}
	finalBytes, err := serializeEvalMultKey(final)
	C.FreeEvalMultKey(final)
	if err != nil {
		return EvalKeyFinal{}, err
	}
	return EvalKeyFinal{EvalMultFinal: finalBytes, EvalSumFinal: evalSumFinal}, nil
}

// --- Streamed (per-index) rotation keygen Go wrappers -------------------------

// StreamedEvalSumKeyGenLeadWithContext is like EvalSumKeyGenLead but generates
// rotation keys one index at a time, freeing C++ memory after each, so peak RAM
// is bounded to a single rotation key rather than the full map.
func StreamedEvalSumKeyGenLeadWithContext(ctx *CryptoContext, secretKeyShare []byte) ([]byte, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, true)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)
	var sum C.RotKeyHandle
	if rc := C.StreamedEvalSumKeyGenLead(ctx.handle, sk, &sum); rc != 0 {
		return nil, fmt.Errorf("streamed eval-sum lead key generation failed")
	}
	defer C.FreeRotKey(sum)
	return serializeRotKey(sum)
}

// StreamedEvalSumKeyShareWithContext is like EvalSumKeyShare but generates one
// index at a time against the lead base.
func StreamedEvalSumKeyShareWithContext(ctx *CryptoContext, secretKeyShare, evalSumBase, ownPublicKey []byte) ([]byte, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, false)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)
	sumBase, err := deserializeRotKey(ctx.handle, evalSumBase)
	if err != nil {
		return nil, err
	}
	defer C.FreeRotKey(sumBase)
	ownPK, err := deserializePublicKey(ctx.handle, ownPublicKey)
	if err != nil {
		return nil, err
	}
	defer C.FreePublicKey(ownPK)
	var sumShare C.RotKeyHandle
	if rc := C.StreamedEvalSumKeyShare(ctx.handle, sk, sumBase, ownPK, &sumShare); rc != 0 {
		return nil, fmt.Errorf("streamed eval-sum share generation failed")
	}
	defer C.FreeRotKey(sumShare)
	return serializeRotKey(sumShare)
}

// MinimalRotationIndicesWithContext returns the rotation-index set configured on
// the context. For MinimalRotationKeys contexts this is the profile/payload set;
// otherwise it is the broadcast set.
func MinimalRotationIndicesWithContext(ctx *CryptoContext) ([]int32, error) {
	var count C.int32_t
	if rc := C.GetMinimalRotationIndices(ctx.handle, nil, &count); rc != 0 {
		return nil, fmt.Errorf("get minimal rotation index count failed")
	}
	if count <= 0 {
		return nil, nil
	}
	buf := make([]C.int32_t, int(count))
	if rc := C.GetMinimalRotationIndices(ctx.handle, &buf[0], &count); rc != 0 {
		return nil, fmt.Errorf("get minimal rotation indices failed")
	}
	out := make([]int32, int(count))
	for i := range out {
		out[i] = int32(buf[i])
	}
	return out, nil
}

func GeneratePerIndexEvalSumKeyWithContext(ctx *CryptoContext, secretKeyShare []byte, index int32) ([]byte, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, true)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)
	var key C.RotKeyHandle
	if rc := C.GeneratePerIndexEvalSumKey(ctx.handle, sk, C.int32_t(index), &key); rc != 0 {
		return nil, fmt.Errorf("per-index eval-sum lead key generation failed for index %d", index)
	}
	defer C.FreeRotKey(key)
	return serializeRotKey(key)
}

func GeneratePerIndexEvalSumKeysWithContext(ctx *CryptoContext, secretKeyShare []byte) ([]IndexedEvalSumKey, error) {
	indices, err := MinimalRotationIndicesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]IndexedEvalSumKey, 0, len(indices))
	for _, index := range indices {
		key, err := GeneratePerIndexEvalSumKeyWithContext(ctx, secretKeyShare, index)
		if err != nil {
			return nil, err
		}
		out = append(out, IndexedEvalSumKey{Index: int(index), Key: key})
	}
	return out, nil
}

func GeneratePerIndexEvalSumShareWithContext(ctx *CryptoContext, secretKeyShare, singleIndexBase, ownPublicKey []byte, index int32) ([]byte, error) {
	sk, err := deserializeSecretKeyShare(ctx.handle, secretKeyShare, false)
	if err != nil {
		return nil, err
	}
	defer C.FreeSecretKeyShare(sk)
	base, err := deserializeRotKey(ctx.handle, singleIndexBase)
	if err != nil {
		return nil, err
	}
	defer C.FreeRotKey(base)
	ownPK, err := deserializePublicKey(ctx.handle, ownPublicKey)
	if err != nil {
		return nil, err
	}
	defer C.FreePublicKey(ownPK)
	var share C.RotKeyHandle
	if rc := C.GeneratePerIndexEvalSumShare(ctx.handle, sk, base, ownPK, C.int32_t(index), &share); rc != 0 {
		return nil, fmt.Errorf("per-index eval-sum share generation failed for index %d", index)
	}
	defer C.FreeRotKey(share)
	return serializeRotKey(share)
}

func GeneratePerIndexEvalSumSharesWithContext(ctx *CryptoContext, secretKeyShare []byte, baseKeys []IndexedEvalSumKey, ownPublicKey []byte) ([]IndexedEvalSumKey, error) {
	if len(baseKeys) == 0 {
		return nil, fmt.Errorf("per-index eval-sum base keys are required")
	}
	out := make([]IndexedEvalSumKey, 0, len(baseKeys))
	for _, base := range baseKeys {
		key, err := GeneratePerIndexEvalSumShareWithContext(ctx, secretKeyShare, base.Key, ownPublicKey, int32(base.Index))
		if err != nil {
			return nil, err
		}
		out = append(out, IndexedEvalSumKey{Index: base.Index, Key: key})
	}
	return out, nil
}

// CombineEvalKeyRound1PerIndexWithContext is the context-reusing variant of
// CombineEvalKeyRound1PerIndex.
func CombineEvalKeyRound1PerIndexWithContext(ctx *CryptoContext, publicKeys [][]byte, evalMultShares [][]byte, evalSumSharesByParty [][]IndexedEvalSumKey) (EvalKeyRound1Combined, error) {
	return combineEvalKeyRound1PerIndex(ctx.handle, publicKeys, evalMultShares, evalSumSharesByParty)
}

// FullFusePayloadCKKSWithContext is like FullFusePayloadCKKS but reuses the
// provided CKKS context instead of creating a new one — eliminates ~4 GB of
// duplicate context memory at ring 2^16.
func FullFusePayloadCKKSWithContext(ctx *CryptoContext, req FullFuseRequest) ([]byte, error) {
	if ctx == nil || ctx.handle == nil {
		return nil, fmt.Errorf("crypto context is required")
	}
	n := len(req.CandidateCiphertexts)
	if n == 0 || len(req.InitiatorCiphertext) == 0 {
		return nil, fmt.Errorf("initiator and at least one candidate ciphertext required")
	}
	if len(req.CandidateLatQ) != n || len(req.CandidateLonQ) != n || len(req.CandidateBrownies) != n || len(req.CandidatePackages) != n {
		return nil, fmt.Errorf("candidate metadata counts must match ciphertext count")
	}
	evalKeysPreinserted := len(req.EvalKeys.EvalMultFinal) == 0 && len(req.EvalKeys.EvalSumFinal) == 0
	if len(req.EvalKeys.EvalMultFinal) == 0 && !evalKeysPreinserted {
		return nil, fmt.Errorf("final eval-mult key is required")
	}
	pkgBytes := req.PackageBytes
	if pkgBytes <= 0 {
		return nil, fmt.Errorf("packageBytes must be positive")
	}
	payloadSlots := req.PayloadSlotCount
	if payloadSlots <= 0 {
		return nil, fmt.Errorf("payloadSlotCount must be positive")
	}
	candidateBlob, candidateLens := concatCandidateCiphertexts(req.CandidateCiphertexts)
	latQ := intsToCInts(req.CandidateLatQ)
	lonQ := intsToCInts(req.CandidateLonQ)
	brownies := intsToCInts(req.CandidateBrownies)
	packages, err := flattenCandidatePackages(req.CandidatePackages, pkgBytes)
	if err != nil {
		return nil, err
	}
	comparator := C.CString(defaultStringGo(req.Comparator, "tanh_chebyshev"))
	defer C.free(unsafe.Pointer(comparator))
	schedule := C.CString(defaultStringGo(req.SelectorSchedule, "none"))
	defer C.free(unsafe.Pointer(schedule))
	minimalFlag := C.int(0)
	if req.MinimalRotationKeys {
		minimalFlag = 1
	}
	var evalSumPtr *C.uint8_t
	var evalSumLen C.size_t
	if len(req.EvalKeys.EvalSumFinal) > 0 {
		evalSumPtr = (*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalSumFinal[0]))
		evalSumLen = C.size_t(len(req.EvalKeys.EvalSumFinal))
	}
	var evalMultPtr *C.uint8_t
	var evalMultLen C.size_t
	if len(req.EvalKeys.EvalMultFinal) > 0 {
		evalMultPtr = (*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalMultFinal[0]))
		evalMultLen = C.size_t(len(req.EvalKeys.EvalMultFinal))
	}
	var out *C.uint8_t
	var outLen C.size_t
	var errBuf [512]C.char
	if rc := C.ARESFullFusePayloadCKKS(
		ctx.handle,                                // reuse caller's context
		C.uint32_t(0), C.double(0), C.uint32_t(0), // ring/scaling/depth: unused when ctx set
		(*C.uint8_t)(unsafe.Pointer(&req.InitiatorCiphertext[0])), C.size_t(len(req.InitiatorCiphertext)),
		(*C.uint8_t)(unsafe.Pointer(&candidateBlob[0])), (*C.size_t)(unsafe.Pointer(&candidateLens[0])),
		(*C.int)(unsafe.Pointer(&latQ[0])), (*C.int)(unsafe.Pointer(&lonQ[0])), (*C.int)(unsafe.Pointer(&brownies[0])),
		C.int(n), C.int(req.ProfileDim),
		C.int(req.InitiatorLatQ), C.int(req.InitiatorLonQ),
		C.double(req.Alpha), C.double(req.Beta), C.double(req.Gamma),
		comparator, C.int(req.ComparatorDegree), C.double(req.ComparatorGain),
		C.double(req.ComparatorScale), C.double(req.ComparatorBound), schedule,
		evalMultPtr, evalMultLen,
		evalSumPtr, evalSumLen,
		(*C.int)(unsafe.Pointer(&packages[0])), C.int(pkgBytes), C.int(payloadSlots),
		minimalFlag, &out, &outLen, &errBuf[0], C.size_t(len(errBuf)),
	); rc != 0 {
		return nil, fmt.Errorf("full fuse payload: %s", C.GoString(&errBuf[0]))
	}
	result := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	C.free(unsafe.Pointer(out))
	return result, nil
}

// ChunkedFusePayloadCKKS builds a fresh CKKS context from params (batch =
// next_pow2(ProfileDim)) and runs the server-blind CHUNKED fusion, returning the
// per-chunk winner-package ciphertexts. req.EvalKeys.EvalSumFinal must be the
// EvalSum-replicate (eval-sum-only) key set generated at batch = next_pow2(ProfileDim).
func ChunkedFusePayloadCKKS(params ContractParams, req FullFuseRequest) ([][]byte, error) {
	n := len(req.CandidateCiphertexts)
	if len(req.InitiatorCiphertext) == 0 {
		return nil, fmt.Errorf("initiator ciphertext is required")
	}
	if n == 0 {
		return nil, fmt.Errorf("at least one candidate ciphertext is required")
	}
	if len(req.CandidateLatQ) != n || len(req.CandidateLonQ) != n || len(req.CandidateBrownies) != n || len(req.CandidatePackages) != n {
		return nil, fmt.Errorf("candidate metadata counts must match ciphertext count")
	}
	if len(req.EvalKeys.EvalMultFinal) == 0 || len(req.EvalKeys.EvalSumFinal) == 0 {
		return nil, fmt.Errorf("final eval-mult and eval-sum keys are required")
	}
	packageBytes := req.PackageBytes
	if packageBytes <= 0 {
		return nil, fmt.Errorf("packageBytes must be positive")
	}
	payloadSlots := req.PayloadSlotCount
	if payloadSlots <= 0 {
		return nil, fmt.Errorf("payloadSlotCount must be positive")
	}
	candidateBlob, candidateLens := concatCandidateCiphertexts(req.CandidateCiphertexts)
	latQ := intsToCInts(req.CandidateLatQ)
	lonQ := intsToCInts(req.CandidateLonQ)
	brownies := intsToCInts(req.CandidateBrownies)
	packages, err := flattenCandidatePackages(req.CandidatePackages, packageBytes)
	if err != nil {
		return nil, err
	}
	comparator := C.CString(defaultStringGo(req.Comparator, "tanh_chebyshev"))
	defer C.free(unsafe.Pointer(comparator))
	schedule := C.CString(defaultStringGo(req.SelectorSchedule, "none"))
	defer C.free(unsafe.Pointer(schedule))
	const maxChunks = 256
	chunkLens := make([]C.size_t, maxChunks)
	var out *C.uint8_t
	var outLen C.size_t
	var nChunks C.int
	var errBuf [512]C.char
	if rc := C.ARESChunkedFusePayloadCKKS(
		nil, // ctx_handle: NULL = create fresh context at batch next_pow2(profile_dim)
		C.uint32_t(params.RingDim), C.double(params.ScalingFactor), C.uint32_t(params.Depth),
		(*C.uint8_t)(unsafe.Pointer(&req.InitiatorCiphertext[0])), C.size_t(len(req.InitiatorCiphertext)),
		(*C.uint8_t)(unsafe.Pointer(&candidateBlob[0])), (*C.size_t)(unsafe.Pointer(&candidateLens[0])),
		(*C.int)(unsafe.Pointer(&latQ[0])), (*C.int)(unsafe.Pointer(&lonQ[0])), (*C.int)(unsafe.Pointer(&brownies[0])),
		C.int(n), C.int(req.ProfileDim),
		C.int(req.InitiatorLatQ), C.int(req.InitiatorLonQ),
		C.double(req.Alpha), C.double(req.Beta), C.double(req.Gamma),
		comparator, C.int(req.ComparatorDegree), C.double(req.ComparatorGain),
		C.double(req.ComparatorScale), C.double(req.ComparatorBound), schedule,
		(*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalMultFinal[0])), C.size_t(len(req.EvalKeys.EvalMultFinal)),
		(*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalSumFinal[0])), C.size_t(len(req.EvalKeys.EvalSumFinal)),
		(*C.int)(unsafe.Pointer(&packages[0])), C.int(packageBytes), C.int(payloadSlots),
		&out, &outLen, (*C.size_t)(unsafe.Pointer(&chunkLens[0])), &nChunks,
		&errBuf[0], C.size_t(len(errBuf)),
	); rc != 0 {
		return nil, fmt.Errorf("chunked fuse payload: %s", C.GoString(&errBuf[0]))
	}
	if int(nChunks) > maxChunks {
		C.free(unsafe.Pointer(out))
		return nil, fmt.Errorf("chunked fuse produced %d chunks > cap %d", int(nChunks), maxChunks)
	}
	blob := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	C.free(unsafe.Pointer(out))
	chunks := make([][]byte, int(nChunks))
	off := 0
	for c := 0; c < int(nChunks); c++ {
		l := int(chunkLens[c])
		chunks[c] = blob[off : off+l]
		off += l
	}
	return chunks, nil
}

// ChunkedFusePayloadCKKSWithContext is the CHUNKED, low-RSS counterpart of
// FullFusePayloadCKKSWithContext: it EvalSum-replicates the mask across the
// profile_dim batch (fold rotation keys only — no broadcast set) and splits the
// payload into ceil(payloadSlots/batch) chunks. Returns the per-chunk winner-package
// ciphertexts; each holds the winner's chunk_size payload bits in slots [0,chunk_size).
// The caller threshold-decrypts each chunk and reassembles the payload. This is the
// server-blind path that runs on the fold-only 7-key rotation set (vs broadcast's 17).
func ChunkedFusePayloadCKKSWithContext(ctx *CryptoContext, req FullFuseRequest) ([][]byte, error) {
	if ctx == nil || ctx.handle == nil {
		return nil, fmt.Errorf("crypto context is required")
	}
	n := len(req.CandidateCiphertexts)
	if n == 0 || len(req.InitiatorCiphertext) == 0 {
		return nil, fmt.Errorf("initiator and at least one candidate ciphertext required")
	}
	if len(req.CandidateLatQ) != n || len(req.CandidateLonQ) != n || len(req.CandidateBrownies) != n || len(req.CandidatePackages) != n {
		return nil, fmt.Errorf("candidate metadata counts must match ciphertext count")
	}
	evalKeysPreinserted := len(req.EvalKeys.EvalMultFinal) == 0 && len(req.EvalKeys.EvalSumFinal) == 0
	if len(req.EvalKeys.EvalMultFinal) == 0 && !evalKeysPreinserted {
		return nil, fmt.Errorf("final eval-mult key is required")
	}
	pkgBytes := req.PackageBytes
	if pkgBytes <= 0 {
		return nil, fmt.Errorf("packageBytes must be positive")
	}
	payloadSlots := req.PayloadSlotCount
	if payloadSlots <= 0 {
		return nil, fmt.Errorf("payloadSlotCount must be positive")
	}
	candidateBlob, candidateLens := concatCandidateCiphertexts(req.CandidateCiphertexts)
	latQ := intsToCInts(req.CandidateLatQ)
	lonQ := intsToCInts(req.CandidateLonQ)
	brownies := intsToCInts(req.CandidateBrownies)
	packages, err := flattenCandidatePackages(req.CandidatePackages, pkgBytes)
	if err != nil {
		return nil, err
	}
	comparator := C.CString(defaultStringGo(req.Comparator, "tanh_chebyshev"))
	defer C.free(unsafe.Pointer(comparator))
	schedule := C.CString(defaultStringGo(req.SelectorSchedule, "none"))
	defer C.free(unsafe.Pointer(schedule))
	var evalSumPtr *C.uint8_t
	var evalSumLen C.size_t
	if len(req.EvalKeys.EvalSumFinal) > 0 {
		evalSumPtr = (*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalSumFinal[0]))
		evalSumLen = C.size_t(len(req.EvalKeys.EvalSumFinal))
	}
	var evalMultPtr *C.uint8_t
	var evalMultLen C.size_t
	if len(req.EvalKeys.EvalMultFinal) > 0 {
		evalMultPtr = (*C.uint8_t)(unsafe.Pointer(&req.EvalKeys.EvalMultFinal[0]))
		evalMultLen = C.size_t(len(req.EvalKeys.EvalMultFinal))
	}
	const maxChunks = 256 // ceil(payloadSlots/batch); 256*32 slots covers any sane payload
	chunkLens := make([]C.size_t, maxChunks)
	var out *C.uint8_t
	var outLen C.size_t
	var nChunks C.int
	var errBuf [512]C.char
	if rc := C.ARESChunkedFusePayloadCKKS(
		ctx.handle,
		C.uint32_t(0), C.double(0), C.uint32_t(0), // ring/scaling/depth unused when ctx set
		(*C.uint8_t)(unsafe.Pointer(&req.InitiatorCiphertext[0])), C.size_t(len(req.InitiatorCiphertext)),
		(*C.uint8_t)(unsafe.Pointer(&candidateBlob[0])), (*C.size_t)(unsafe.Pointer(&candidateLens[0])),
		(*C.int)(unsafe.Pointer(&latQ[0])), (*C.int)(unsafe.Pointer(&lonQ[0])), (*C.int)(unsafe.Pointer(&brownies[0])),
		C.int(n), C.int(req.ProfileDim),
		C.int(req.InitiatorLatQ), C.int(req.InitiatorLonQ),
		C.double(req.Alpha), C.double(req.Beta), C.double(req.Gamma),
		comparator, C.int(req.ComparatorDegree), C.double(req.ComparatorGain),
		C.double(req.ComparatorScale), C.double(req.ComparatorBound), schedule,
		evalMultPtr, evalMultLen,
		evalSumPtr, evalSumLen,
		(*C.int)(unsafe.Pointer(&packages[0])), C.int(pkgBytes), C.int(payloadSlots),
		&out, &outLen, (*C.size_t)(unsafe.Pointer(&chunkLens[0])), &nChunks,
		&errBuf[0], C.size_t(len(errBuf)),
	); rc != 0 {
		return nil, fmt.Errorf("chunked fuse payload: %s", C.GoString(&errBuf[0]))
	}
	if int(nChunks) > maxChunks {
		C.free(unsafe.Pointer(out))
		return nil, fmt.Errorf("chunked fuse produced %d chunks > cap %d", int(nChunks), maxChunks)
	}
	blob := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	C.free(unsafe.Pointer(out))
	chunks := make([][]byte, int(nChunks))
	off := 0
	for c := 0; c < int(nChunks); c++ {
		l := int(chunkLens[c])
		chunks[c] = blob[off : off+l]
		off += l
	}
	return chunks, nil
}

// UnionComparator is one comparator shot in a chunked union score (e.g. the
// CKKSRing32KUnionV1 trio tanh_g5_d13 / logi_g4_b5_d13 / logi_g3_b6_d13). InputScale is the
// per-comparator range control: a comparator's valid score-diff range is ±Bound/InputScale,
// so steep logistics need InputScale < 1 to keep larger margins inside their approximation
// interval (out-of-range eval → "approximation error too high" on decrypt).
type UnionComparator struct {
	ID          string
	Comparator  string // "selector" | "logistic" | "tanh_chebyshev"
	Schedule    string // selector-sharpen schedule, e.g. "smoothstep5" or "none"
	Gain        float64
	Bound       float64
	InputScale  float64 // output
	RangeMargin float64 // input: raw score-diff range this comparator should cover; 0 = metadata default
	Degree      int
}

// DistributionMetadata describes the score spread a deployment expects. MedianMargin
// is the top-2 winner margin and drives score amplification. MaxMargin is the maximum
// observed top-2 margin. MaxPairwiseDiff is the maximum observed score gap between any
// two candidates in a cohort and drives comparator range control. The comparators'
// characters (gain/bound/shape — their diversity) stay fixed; only the
// distribution-dependent score amplification and per-comparator InputScale are derived.
// Margins are in raw score units; supply them directly or compute via
// MarginStatsFromCohorts for profile-only cosine cohorts.
type DistributionMetadata struct {
	MinMargin       float64
	MedianMargin    float64
	MaxMargin       float64
	MaxPairwiseDiff float64
}

// MarginStatsFromCohorts computes DistributionMetadata from sample cohorts: each entry is
// the initiator's unit profile followed by the candidate unit profiles. Lets a developer
// hand ARES-core representative profile-only embeddings instead of raw stats.
func MarginStatsFromCohorts(cohorts [][][]float64) DistributionMetadata {
	margins := make([]float64, 0, len(cohorts))
	maxPairwise := 0.0
	for _, ch := range cohorts {
		if len(ch) < 3 {
			continue
		}
		init := ch[0]
		best, second, worst := math.Inf(-1), math.Inf(-1), math.Inf(1)
		for _, cand := range ch[1:] {
			var d float64
			for i := 0; i < len(init) && i < len(cand); i++ {
				d += init[i] * cand[i]
			}
			if d > best {
				second, best = best, d
			} else if d > second {
				second = d
			}
			if d < worst {
				worst = d
			}
		}
		margins = append(margins, best-second)
		if pairwise := best - worst; pairwise > maxPairwise {
			maxPairwise = pairwise
		}
	}
	if len(margins) == 0 {
		return DistributionMetadata{MinMargin: 0.005, MedianMargin: 0.0126, MaxMargin: 0.05, MaxPairwiseDiff: 0.05}
	}
	sort.Float64s(margins)
	if maxPairwise <= 0 {
		maxPairwise = margins[len(margins)-1]
	}
	return DistributionMetadata{
		MinMargin:       margins[0],
		MedianMargin:    margins[len(margins)/2],
		MaxMargin:       margins[len(margins)-1],
		MaxPairwiseDiff: maxPairwise,
	}
}

// TuneUnion derives the score amplification (Beta) and per-comparator InputScale while
// preserving each comparator's native gain/bound (its sharpness/width = the union's
// diversity). Beta maps the median top-2 margin to `target` score-diff units. Each
// comparator then covers either its own RangeMargin or the metadata's widest observed
// range, so callers can deliberately tune one comparator for close contests and another
// for the wide tail. Returns the tuned ScoreScale (Beta) and comparator set.
func TuneUnion(meta DistributionMetadata, base []UnionComparator, target float64) (scoreScale float64, tuned []UnionComparator) {
	if target <= 0 {
		target = 4
	}
	med := meta.MedianMargin
	if med <= 0 {
		med = 0.0126
	}
	scoreScale = 2 * target / med
	rangeMargin := meta.MaxMargin
	if meta.MaxPairwiseDiff > rangeMargin {
		rangeMargin = meta.MaxPairwiseDiff
	}
	tuned = make([]UnionComparator, len(base))
	for i, c := range base {
		c2 := c
		compRangeMargin := rangeMargin
		if c2.RangeMargin > 0 {
			compRangeMargin = c2.RangeMargin
		}
		compMaxDiff := (scoreScale / 2) * compRangeMargin
		if compMaxDiff <= 0 {
			compMaxDiff = target
		}
		if c2.Bound > 0 {
			c2.InputScale = c2.Bound / (compMaxDiff * 1.15) // 15% headroom past the selected range
			if c2.InputScale > 1 {
				c2.InputScale = 1
			}
		} else {
			// selector cubic f(x)=0.5+0.1125x-0.00084375x^3 is monotonic up to x~6.7 (its peak);
			// scale so the LARGEST margin lands near that peak, not past it (where it turns over
			// and inverts). Over-compressing (mapping maxDiff well below the peak) flattens the
			// selector and kills its separation -- the bug that dropped ss5 to 1/10.
			const selectorPeak = 6.7
			c2.InputScale = selectorPeak / (compMaxDiff * 1.05)
			if c2.InputScale > 1 {
				c2.InputScale = 1
			}
		}
		tuned[i] = c2
	}
	return scoreScale, tuned
}

// ChunkedUnionScoreCKKS is the DEFAULT server-blind union scoring path. It builds ONE CKKS
// context and reuses it across every comparator (instead of a fresh ~GB context per shot —
// the low-RSS win) and runs each comparator's chunked fusion on it, returning the
// per-comparator per-chunk winner-package ciphertexts: out[i] is comparator i's chunk
// ciphertexts. The caller threshold-decrypts each comparator's chunks and accepts the cohort
// if any comparator's reassembled package opens. Prefer this over per-call
// ChunkedFusePayloadCKKS (which allocates a fresh context for every comparator).
func ChunkedUnionScoreCKKS(params ContractParams, req FullFuseRequest, comparators []UnionComparator) ([][][]byte, error) {
	return ChunkedUnionScoreCKKSWithConcurrency(params, req, comparators, 1)
}

// ChunkedUnionScoreCKKSWithConcurrency is the comparator-fanout variant of
// ChunkedUnionScoreCKKS. It still creates exactly one CKKS context and reuses it across
// all comparator lanes; concurrency only controls how many comparator fusions are in-flight
// against that shared context.
func ChunkedUnionScoreCKKSWithConcurrency(params ContractParams, req FullFuseRequest, comparators []UnionComparator, concurrency int) ([][][]byte, error) {
	if len(comparators) == 0 {
		return nil, fmt.Errorf("at least one union comparator is required")
	}
	concurrency = clampUnionConcurrency(concurrency, comparators)
	ctx, err := NewCryptoContext(params)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	usePreinsertedEvalKeys := concurrency > 1
	if usePreinsertedEvalKeys {
		if err := insertUnionEvalKeys(ctx, req.EvalKeys); err != nil {
			return nil, err
		}
	}
	return runUnionComparators(ctx, req, comparators, concurrency, usePreinsertedEvalKeys)
}

// runUnionComparators fuses every comparator lane against an already-built CKKS
// context. When usePreinsertedEvalKeys is true the eval-mult/eval-sum keys are
// assumed to already live in the context (each lane passes no key bytes), which
// is required for concurrency > 1 so lanes don't race on per-call clear/insert.
func runUnionComparators(ctx *CryptoContext, req FullFuseRequest, comparators []UnionComparator, concurrency int, usePreinsertedEvalKeys bool) ([][][]byte, error) {
	out := make([][][]byte, len(comparators))
	if concurrency == 1 {
		for i, comp := range comparators {
			chunks, err := chunkedUnionComparatorWithContext(ctx, req, comp, usePreinsertedEvalKeys)
			if err != nil {
				return nil, fmt.Errorf("union comparator %s: %w", comp.ID, err)
			}
			out[i] = chunks
		}
		return out, nil
	}

	type result struct {
		index  int
		id     string
		chunks [][]byte
		err    error
	}
	jobs := make(chan int)
	results := make(chan result, len(comparators))
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				chunks, err := chunkedUnionComparatorWithContext(ctx, req, comparators[i], usePreinsertedEvalKeys)
				results <- result{index: i, id: comparators[i].ID, chunks: chunks, err: err}
			}
		}()
	}
	go func() {
		for i := range comparators {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var firstErr error
	for res := range results {
		if res.err != nil && firstErr == nil {
			firstErr = fmt.Errorf("union comparator %s: %w", res.id, res.err)
			continue
		}
		out[res.index] = res.chunks
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// ChunkedUnionScoreCKKSWithEvalSumRefs is the per-index (b-only / CRS-seeded)
// eval-sum counterpart of ChunkedUnionScoreCKKSWithConcurrency. The threshold
// eval-sum fold keys arrive as per-index refs (a/b vectors resolved via resolve)
// rather than one monolithic serialized key blob, so this reconstructs them — and
// the eval-mult key — once into a single shared context, then fuses every
// comparator lane against that context with the keys preinserted. It is the union
// analog of FullFusePayloadCKKSWithEvalSumRefs.
func ChunkedUnionScoreCKKSWithEvalSumRefs(params ContractParams, req FullFuseRequest, comparators []UnionComparator, concurrency int, publicKeys [][]byte, evalSumRefsByParty [][]IndexedEvalSumKeyRef, resolve EvalSumKeyResolver) ([][][]byte, error) {
	if len(comparators) == 0 {
		return nil, fmt.Errorf("at least one union comparator is required")
	}
	if len(req.EvalKeys.EvalMultFinal) == 0 {
		return nil, fmt.Errorf("final eval-mult key is required")
	}
	concurrency = clampUnionConcurrency(concurrency, comparators)
	ctx, err := NewCryptoContext(params)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	// Preinsert the eval-mult key once (every lane reuses it; per-lane clear/insert
	// would race the shared context under concurrency).
	multKey, err := deserializeEvalMultKey(ctx.handle, req.EvalKeys.EvalMultFinal)
	if err != nil {
		return nil, fmt.Errorf("deserialize eval-mult key: %w", err)
	}
	defer C.FreeEvalMultKey(multKey)
	if rc := C.InsertEvalMultKey(ctx.handle, multKey); rc != 0 {
		return nil, fmt.Errorf("insert eval-mult key failed")
	}
	// Reconstruct + preinsert the per-index eval-sum fold keys (b-only / CRS path).
	if err := insertEvalSumPerIndexLazy(ctx.handle, publicKeys, evalSumRefsByParty, resolve); err != nil {
		return nil, err
	}
	return runUnionComparators(ctx, req, comparators, concurrency, true)
}

func clampUnionConcurrency(concurrency int, comparators []UnionComparator) int {
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(comparators) {
		return len(comparators)
	}
	return concurrency
}

func insertUnionEvalKeys(ctx *CryptoContext, evalKeys EvalKeyFinal) error {
	if len(evalKeys.EvalMultFinal) == 0 || len(evalKeys.EvalSumFinal) == 0 {
		return fmt.Errorf("final eval-mult and eval-sum keys are required")
	}
	multKey, err := deserializeEvalMultKey(ctx.handle, evalKeys.EvalMultFinal)
	if err != nil {
		return fmt.Errorf("deserialize eval-mult key: %w", err)
	}
	defer C.FreeEvalMultKey(multKey)
	if rc := C.InsertEvalMultKey(ctx.handle, multKey); rc != 0 {
		return fmt.Errorf("insert eval-mult key failed")
	}
	sumKey, err := deserializeRotKey(ctx.handle, evalKeys.EvalSumFinal)
	if err != nil {
		return fmt.Errorf("deserialize eval-sum key: %w", err)
	}
	defer C.FreeRotKey(sumKey)
	if rc := C.InsertEvalSumKey(ctx.handle, sumKey); rc != 0 {
		return fmt.Errorf("insert eval-sum key failed")
	}
	return nil
}

func unionComparatorRequest(req FullFuseRequest, comp UnionComparator, usePreinsertedEvalKeys bool) FullFuseRequest {
	r := req
	r.Comparator = comp.Comparator
	r.SelectorSchedule = comp.Schedule
	r.ComparatorGain = comp.Gain
	r.ComparatorBound = comp.Bound
	r.ComparatorScale = comp.InputScale
	r.ComparatorDegree = comp.Degree
	if usePreinsertedEvalKeys {
		r.EvalKeys = EvalKeyFinal{}
	}
	return r
}

func chunkedUnionComparatorWithContext(ctx *CryptoContext, req FullFuseRequest, comp UnionComparator, usePreinsertedEvalKeys bool) ([][]byte, error) {
	r := unionComparatorRequest(req, comp, usePreinsertedEvalKeys)
	return ChunkedFusePayloadCKKSWithContext(ctx, r)
}

// FullFusePayloadCKKSWithEvalSumRefs streams per-index eval-sum shares into a
// native context before running fused scoring. It avoids constructing or passing a
// monolithic serialized eval-sum key blob through Go.
func FullFusePayloadCKKSWithEvalSumRefs(params ContractParams, req FullFuseRequest, publicKeys [][]byte, evalSumRefsByParty [][]IndexedEvalSumKeyRef, resolve EvalSumKeyResolver) ([]byte, error) {
	if len(req.EvalKeys.EvalMultFinal) == 0 {
		return nil, fmt.Errorf("final eval-mult key is required")
	}
	ctx, err := NewCryptoContext(params)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if err := insertEvalSumPerIndexLazy(ctx.handle, publicKeys, evalSumRefsByParty, resolve); err != nil {
		return nil, err
	}
	streamReq := req
	streamReq.EvalKeys.EvalSumFinal = nil
	return FullFusePayloadCKKSWithContext(ctx, streamReq)
}

// concatCandidateCiphertexts flattens candidate ciphertexts into one blob with length array.
func concatCandidateCiphertexts(cts [][]byte) ([]byte, []C.size_t) {
	lens := make([]C.size_t, len(cts))
	var blob []byte
	for i, ct := range cts {
		lens[i] = C.size_t(len(ct))
		blob = append(blob, ct...)
	}
	return blob, lens
}
