// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package fhecalib

import (
	"fmt"
	"strings"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// cgoHandle implements ContextHandle against the in-process OpenFHE bridge for
// one provisioned (depth-specific) context.
type cgoHandle struct {
	params      helperclient.ContractParams
	cgoParams   cgo.ContractParams
	evalMultKey []byte
}

func (h *cgoHandle) Params() helperclient.ContractParams { return h.params }

func (h *cgoHandle) EvalMult(ctA, ctB []byte) ([]byte, error) {
	return cgo.EvalMultCKKSForContract(h.cgoParams, h.evalMultKey, ctA, ctB)
}

// buildJointEvalMultN2 mirrors buildJointEvalMult in
// helperclient/argmax_e2e_test.go: the two-round eval-mult-key chain for the
// given key shares. Returns the joint eval-mult key.
func buildJointEvalMultN2(params cgo.ContractParams, shares []cgo.DistributedKeyShare) ([]byte, error) {
	finalPK := shares[len(shares)-1].PublicKey
	lead, err := cgo.EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return nil, fmt.Errorf("evalkey round1 lead: %w", err)
	}
	pks := make([][]byte, len(shares))
	mr1 := make([][]byte, len(shares))
	sr1 := make([][]byte, len(shares))
	pks[0], mr1[0], sr1[0] = shares[0].PublicKey, lead.EvalMultBase, lead.EvalSumBase
	for i := 1; i < len(shares); i++ {
		r1, err := cgo.EvalKeyRound1Participant(params, shares[i].SecretKeyShare,
			lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("evalkey round1 participant %d: %w", i, err)
		}
		pks[i] = shares[i].PublicKey
		mr1[i] = r1.EvalMultSwitchShare
		sr1[i] = r1.EvalSumShare
	}
	combined, err := cgo.CombineEvalKeyRound1(params, pks, mr1, sr1)
	if err != nil {
		return nil, fmt.Errorf("combine round1: %w", err)
	}
	fs := make([][]byte, len(shares))
	for i := range shares {
		r2, err := cgo.EvalKeyRound2Participant(params, shares[i].SecretKeyShare,
			combined.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			return nil, fmt.Errorf("evalkey round2 participant %d: %w", i, err)
		}
		fs[i] = r2.EvalMultFinalShare
	}
	final, err := cgo.CombineEvalKeyRound2(params, finalPK, fs, combined.EvalSumFinal)
	if err != nil {
		return nil, fmt.Errorf("combine round2: %w", err)
	}
	return final.EvalMultFinal, nil
}

// Calibrate finds the minimum depth for cut over a minimal n=2 threshold
// context. Depth/precision are party-count-independent, so n=2 (the keygen
// floor) yields the same answer as a single key for far less work.
// profileDim is the slot count the use-case vectors occupy.
func Calibrate(cut CircuitUnderTest, p CalibrationParams, profileDim int) (CalibrationResult, error) {
	if err := cgo.SmokeCKKS(); err != nil {
		return CalibrationResult{}, fmt.Errorf("fhecalib: OpenFHE unavailable: %w", err)
	}
	inputs := cut.Inputs()
	want := cut.Expected(inputs)

	runAtDepth := func(depth uint32) (float64, bool, error) {
		cgoParams := cgo.DefaultContractParams(profileDim, depth)

		first, err := cgo.DistributedKeyGenFirst(cgoParams)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("keygen first: %w", err)
		}
		second, err := cgo.DistributedKeyGenNext(cgoParams, first.PublicKey)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("keygen next: %w", err)
		}
		shares := []cgo.DistributedKeyShare{first, second}
		evalMultKey, err := buildJointEvalMultN2(cgoParams, shares)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, err
		}
		jointPK := second.PublicKey

		encIn := make([][]byte, len(inputs))
		for i, vec := range inputs {
			ct, err := cgo.EncryptCKKSForContract(cgoParams, jointPK, vec)
			if err != nil {
				if isModulusCap(err) {
					return 0, true, nil
				}
				return 0, false, fmt.Errorf("encrypt input %d: %w", i, err)
			}
			encIn[i] = ct
		}

		h := &cgoHandle{
			params: helperclient.ContractParams{
				RingDim:        cgoParams.RingDim,
				Depth:          depth,
				ScalingModSize: p.Base.ScalingModSize,
			},
			cgoParams:   cgoParams,
			evalMultKey: evalMultKey,
		}
		encOut, err := cut.Eval(h, encIn)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("circuit eval: %w", err)
		}

		// Threshold-decrypt (n=2): lead = first share, follower = second.
		// Mirrors cgo.ThresholdSmokeCKKS's partial-decrypt + fuse sequence.
		p0, err := cgo.PartialDecryptCKKSForContract(cgoParams, encOut, first.SecretKeyShare, true)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("partial decrypt lead: %w", err)
		}
		p1, err := cgo.PartialDecryptCKKSForContract(cgoParams, encOut, second.SecretKeyShare, false)
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("partial decrypt follower: %w", err)
		}
		got, err := cgo.FuseCKKSPartialsForContract(cgoParams, [][]byte{p0, p1}, len(want))
		if err != nil {
			if isModulusCap(err) {
				return 0, true, nil
			}
			return 0, false, fmt.Errorf("fuse partials: %w", err)
		}

		return maxSlotAbsError(got, want), false, nil
	}

	res, err := sweep(p, runAtDepth)
	res.Circuit = cut.Name()
	return res, err
}

// isModulusCap reports whether an OpenFHE provisioning error indicates the
// requested depth needs a ciphertext modulus larger than RingDim permits.
// The exact matching substrings are finalized in Task 3 against the real
// OpenFHE error string.
func isModulusCap(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range modulusCapMarkers {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

var modulusCapMarkers = []string{
	"modulus", "exceeds", "ring dimension", "security", "hestd",
}
