// SPDX-License-Identifier: Apache-2.0
//go:build openfhe
package cgo_test

import (
	"fmt"
	"testing"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
)

func TestSingleKey_TiebreakCloseDistances(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}

	// Realistic weights from the spec: K dominates, WStar/WDist are tiebreak-only
	const (
		K     = 100.0  // price strictly dominant
		WStar = 5.0    // max ★ penalty range 0..5 (= 5 - starNorm)
		WDist = 10.0   // dist² weight
	)

	// Test: identical prices & stars, varying ONLY dist² — extreme tiebreak
	for n := 2; n <= 5; n++ {
		n := n
		for _, gap := range []float64{0.01, 0.005, 0.001} {
			t.Run(fmt.Sprintf("n=%d-gap=%.3f", n, gap), func(t *testing.T) {
				// All identical price (€15.00 → normalized to ~0.5 in [0,1])
				// All identical ★ (4.5 → penalty = 5-4.5 = 0.5)
				// Varying dist² from 0 up by gap each
				scores := make([]float64, n)
				baseNormPrice := 0.5
				baseStarPen := 0.5
				for i := 0; i < n; i++ {
					distSq := float64(i) * gap // driver 0 is closest
					// key = K·normPrice + WStar·starPen + WDist·dist²
					// Best driver has SMALLEST key → negate for argmax
					key := K*baseNormPrice + WStar*baseStarPen + WDist*distSq
					scores[i] = -key // argmax picks max → picks min key = closest driver
				}
				// Scale scores to keep differences in [-1,1] for the polynomial
				scale := 0.5 / (WDist * float64(n-1) * gap + 0.01)
				for i := range scores {
					scores[i] *= scale
				}

				masks, best, err := cgo.SingleKeySoftArgmin(scores, 1)
				if err != nil {
					t.Fatalf("n=%d gap=%.3f: %v", n, gap, err)
				}
				expected := 0 // closest driver always wins
				if best != expected {
					t.Errorf("n=%d gap=%.3f: winner=%d expected=%d masks=%v",
						n, gap, best, expected, fmtMasksTie(masks))
					return
				}
				// Check separation: winner mask should be noticeably larger than runner-up
				if best == 0 && n >= 2 {
					sep := masks[0] - masks[1]
					t.Logf("n=%d gap=%.3f: masks=%v winner=0 sep=%.6f", n, gap, fmtMasksTie(masks), sep)
					if sep <= 0 {
						t.Errorf("n=%d gap=%.3f: zero or negative separation: masks=%v", n, gap, masks)
					}
				}
			})
		}
	}
}

func TestSingleKey_TiebreakWithNoiseFloor(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}

	// Find the minimum resolvable gap: how close can two scores be
	// before the soft-mask can no longer separate them?
	for n := 2; n <= 5; n++ {
		n := n
		t.Run(fmt.Sprintf("noisefloor-n=%d", n), func(t *testing.T) {
			// Win by epsilon: driver 0 score = 0.0, all others = -epsilon
			for _, eps := range []float64{0.1, 0.05, 0.02, 0.01, 0.005, 0.002, 0.001} {
				scores := make([]float64, n)
				scores[0] = 0.0
				for i := 1; i < n; i++ {
					scores[i] = -eps
				}
				masks, best, err := cgo.SingleKeySoftArgmin(scores, 1)
				if err != nil {
					t.Logf("  n=%d eps=%.3f: %v", n, eps, err)
					return
				}
				if best != 0 {
					t.Logf("  n=%d eps=%.3f: NOISE FLOOR — winner=%d masks=%v", n, eps, best, fmtMasksTie(masks))
				}
				sep := masks[0]
				if n >= 2 {
					sep -= masks[1]
				}
				ok := "OK"
				if best != 0 {
					ok = "LOST"
				}
				t.Logf("  eps=%.3f: sep=%.6f %s", eps, sep, ok)
				if best == 0 && sep <= 0 {
					t.Logf("  eps=%.3f: PICKED correctly but NO separation margin", eps)
				}
			}
		})
	}
}

func fmtMasksTie(v []float64) string {
	s := "["
	for i, x := range v {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("%.4f", x)
	}
	return s + "]"
}
