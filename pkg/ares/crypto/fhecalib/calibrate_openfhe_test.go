// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package fhecalib

import (
	"errors"
	"testing"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

func TestCalibrate_SquareCircuitFindsDepth1(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	cut := squareCircuit{in: []float64{0.5, -0.3, 0.25, 0.1}}
	res, err := Calibrate(cut, CalibrationParams{
		Base:       helperclient.ContractParams{RingDim: 1 << 14, ScalingModSize: 50},
		StartDepth: 1,
		MaxDepth:   4,
		Tolerance:  0.01,
	}, 4 /* profileDim = slot count */)
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if !res.Passed {
		t.Fatalf("expected pass, got best err %v", res.AchievedAbsError)
	}
	if res.Depth != 1 {
		t.Fatalf("square needs depth 1, calibrator found %d", res.Depth)
	}
	if res.Circuit != "elementwise-square" {
		t.Fatalf("circuit name not propagated: %q", res.Circuit)
	}
}

func TestCalibrate_ModulusCapSurfaces(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	cut := squareCircuit{in: []float64{0.5, 0.5}}
	// RingDim=2048, ScalingModSize=50, firstMod=60 ⟹ budget exhausted at depth≥40
	// (60 + 40*50 = 2060 ≥ 2048). Start the sweep at depth=40 to guarantee the
	// pre-flight budget check fires immediately on the first candidate.
	_, err := Calibrate(cut, CalibrationParams{
		Base:       helperclient.ContractParams{RingDim: 1 << 11, ScalingModSize: 50},
		StartDepth: 40,
		MaxDepth:   60,
		Tolerance:  0.01,
	}, 2)
	if err == nil {
		t.Fatal("expected an error (modulus cap) at tiny RingDim with high depth")
	}
	if !errors.Is(err, ErrModulusCap) {
		t.Logf("got non-ErrModulusCap error: %v", err)
		t.Log("ACTION: capture this exact error string and add a matching substring to modulusCapMarkers in calibrate_openfhe.go, then re-run")
		t.Fatal("modulus-cap not classified as ErrModulusCap; update modulusCapMarkers")
	}
}
