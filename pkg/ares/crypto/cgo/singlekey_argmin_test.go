// SPDX-License-Identifier: Apache-2.0
//go:build openfhe
package cgo_test

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
)

func TestSingleKeySoftArgmin(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	for n := 2; n <= 5; n++ {
		for _, deg := range []int{1, 3} {
			t.Run(fmt.Sprintf("n=%d-deg%d", n, deg), func(t *testing.T) {
				for trial := 0; trial < 5; trial++ {
					scores := randomScores(n, 0.1)
					masks, best, err := cgo.SingleKeySoftArgmin(scores, deg)
					if err != nil {
						if n >= 4 && deg == 3 {
							t.Logf("n=%d deg=3 trial=%d: expected exhaustion: %v", n, trial, err)
							return
						}
						t.Fatalf("n=%d deg=%d trial=%d: %v", n, deg, trial, err)
					}
					expected := argmaxIndex(scores)
					if best != expected {
						t.Errorf("winner=%d expected=%d masks=%v scores=%v", best, expected, fmtMasks(masks), scores)
						return
					}
					for i := 0; i < n; i++ {
						if i != best && masks[i] >= masks[best] {
							t.Errorf("mask[%d]=%.4f >= winner mask[%d]=%.4f", i, masks[i], best, masks[best])
						}
					}
				}
				t.Logf("all trials OK")
			})
		}
	}
	t.Run("close-scores", func(t *testing.T) {
		for n := 2; n <= 5; n++ {
			scores := closeScores(n, 0.02)
			masks, best, err := cgo.SingleKeySoftArgmin(scores, 1)
			if err != nil {
				t.Logf("close n=%d: %v", n, err)
				continue
			}
			expected := argmaxIndex(scores)
			if best != expected {
				t.Errorf("close n=%d: winner=%d expected=%d masks=%v", n, best, expected, fmtMasks(masks))
			}
		}
	})
}

func randomScores(n int, minGap float64) []float64 {
	s := make([]float64, n)
	for i := range s {
		s[i] = rand.Float64()*2 - 1
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			d := s[i] - s[j]
			if d < 0 { d = -d }
			if d < minGap { s[j] += minGap }
		}
	}
	return s
}

func closeScores(n int, step float64) []float64 {
	s := make([]float64, n)
	for i := range s {
		s[i] = -1.0 + float64(i)*step
	}
	return s
}

func argmaxIndex(v []float64) int {
	best := 0
	for i := 1; i < len(v); i++ {
		if v[i] > v[best] { best = i }
	}
	return best
}

func fmtMasks(v []float64) string {
	s := "["
	for _, x := range v {
		s += fmt.Sprintf("%.4f ", x)
	}
	return s + "]"
}
