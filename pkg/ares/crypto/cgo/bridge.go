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
	"unsafe"
)

type ContractParams struct {
	RingDim       uint32
	ScalingFactor float64
	Depth         uint32
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
	sumShares, freeSumShares, err := deserializeRotKeys(ctx, evalSumShares)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	defer freeSumShares()

	var joined C.EvalMultKeyHandle
	if rc := C.CombineEvalMultSwitchShares(ctx, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.EvalMultKeyHandle)(unsafe.Pointer(&multShares[0])), C.int(len(multShares)), &joined); rc != 0 {
		return EvalKeyRound1Combined{}, fmt.Errorf("eval-mult switch-share combination failed")
	}
	defer C.FreeEvalMultKey(joined)
	joinedBytes, err := serializeEvalMultKey(joined)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}

	var sumFinal C.RotKeyHandle
	if rc := C.CombineEvalSumKeys(ctx, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.RotKeyHandle)(unsafe.Pointer(&sumShares[0])), C.int(len(sumShares)), &sumFinal); rc != 0 {
		return EvalKeyRound1Combined{}, fmt.Errorf("eval-sum share combination failed")
	}
	defer C.FreeRotKey(sumFinal)
	sumFinalBytes, err := serializeRotKey(sumFinal)
	if err != nil {
		return EvalKeyRound1Combined{}, err
	}
	return EvalKeyRound1Combined{EvalMultJoined: joinedBytes, EvalSumFinal: sumFinalBytes}, nil
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
	schedule := C.CString(defaultStringGo(req.SelectorSchedule, "smoothstep5,smoothstep5,smoothstep5,smoothstep7"))
	defer C.free(unsafe.Pointer(schedule))

	var out *C.uint8_t
	var outLen C.size_t
	var errBuf [512]C.char
	if rc := C.ARESFullFusePayloadCKKS(
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
	ctx := C.CreateCKKSContext(C.uint32_t(params.RingDim), C.double(params.ScalingFactor), C.uint32_t(params.Depth))
	if ctx == nil {
		return nil, fmt.Errorf("failed to create OpenFHE contract context")
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
	ctx := C.CreateCKKSContext(C.uint32_t(1024), C.double(float64(uint64(1)<<50)), C.uint32_t(4))
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
