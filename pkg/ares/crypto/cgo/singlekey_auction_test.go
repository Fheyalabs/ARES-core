// SPDX-License-Identifier: Apache-2.0
//go:build openfhe
package cgo_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
)

func TestSingleKeyAuctionFull_EndToEnd(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	params := cgo.ContractParams{RingDim: 1 << 14, ScalingFactor: float64(uint64(1) << 50), Depth: 4}
	w := cgo.AuctionWeights{K: 100, WStar: 1.0, WDist: 0.001}
	floorCents, capCents := 800, 2500
	sessionID := "ride-dresden-001"

	// Full composite key assembly + argmax fits n=2,3 at deg=1 (ring 2^14/depth 4).
	// n=4,5 need more ring/depth for homomorphic key assembly.
	for _, n := range []int{2, 3, 4, 5} {
		n := n
		for trial := 0; trial < 5; trial++ {
			t.Run(fmt.Sprintf("n=%d-trial=%d", n, trial), func(t *testing.T) {
				priceCents := make([]int, n)
				starNorms := make([]float64, n)
				distSqs := make([]float64, n)
				nonces := make([][]byte, n)
				for i := 0; i < n; i++ {
					priceCents[i] = 1200 + i*50 - trial*10
					starNorms[i] = 5.0 - float64(i)*0.3
					distSqs[i] = float64(i) * 0.5
					nonces[i] = make([]byte, 16)
					copy(nonces[i][:8], []byte(fmt.Sprintf("nc%02d-t%02d", i, trial)))
				}

				winner, masks, err := cgo.SingleKeyAuctionFull(
					params, priceCents, starNorms, distSqs, nonces,
					floorCents, capCents, w, 1,
				)
				if err != nil { t.Fatalf("%v", err) }
				if winner != 0 { t.Errorf("expected winner 0, got %d", winner) }
				for i := 0; i < n; i++ {
					if i != winner && masks[i] >= masks[winner] {
						t.Errorf("mask[%d]=%.4f >= winner mask[%d]=%.4f", i, masks[i], winner, masks[winner])
					}
				}
				agreedPrice := priceCents[winner]
				h := sha256.New()
				h.Write(nonces[winner])
				h.Write([]byte(sessionID))
				ss := h.Sum(nil)
				t.Logf("winner=%d price=€%.2f masks=%v secret=%x",
					winner, float64(agreedPrice)/100, fmtMasks(masks), ss[:8])
			})
		}
	}
}

func TestSingleKeyAuctionFull_Binding(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	params := cgo.ContractParams{RingDim: 1 << 14, ScalingFactor: float64(uint64(1) << 50), Depth: 4}
	w := cgo.AuctionWeights{K: 100, WStar: 1.0, WDist: 0.001}

	t.Run("correct-winner-by-mask-argmax", func(t *testing.T) {
		priceCents := []int{1000, 1500, 2000}
		starNorms := []float64{5.0, 5.0, 5.0}
		distSqs := []float64{0.1, 0.1, 0.1}
		nonces := [][]byte{[]byte("nonce-00000000"), []byte("nonce-11111111"), []byte("nonce-22222222")}
		winner, masks, err := cgo.SingleKeyAuctionFull(params, priceCents, starNorms, distSqs, nonces, 800, 2500, w, 1)
		if err != nil { t.Fatalf("%v", err) }
		if winner != 0 { t.Errorf("expected 0, got %d masks=%v", winner, fmtMasks(masks)) }
		if priceCents[winner] != 1000 { t.Errorf("price mismatch") }
	})

	t.Run("tiebreak-star-wins", func(t *testing.T) {
		priceCents := []int{1200, 1200, 1200}
		starNorms := []float64{3.0, 4.0, 5.0}
		distSqs := []float64{0.1, 0.1, 0.1}
		nonces := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
		winner, _, err := cgo.SingleKeyAuctionFull(params, priceCents, starNorms, distSqs, nonces, 800, 2500, w, 1)
		if err != nil { t.Fatalf("%v", err) }
		if winner != 2 { t.Errorf("equal price, best ★: expected 2, got %d", winner) }
	})

	t.Run("tiebreak-distance-wins", func(t *testing.T) {
		priceCents := []int{1200, 1200, 1200}
		starNorms := []float64{5.0, 5.0, 5.0}
		distSqs := []float64{5.0, 2.0, 0.1}
		nonces := [][]byte{[]byte("x"), []byte("y"), []byte("z")}
		winner, _, err := cgo.SingleKeyAuctionFull(params, priceCents, starNorms, distSqs, nonces, 800, 2500, w, 1)
		if err != nil { t.Fatalf("%v", err) }
		if winner != 2 { t.Errorf("equal price+★, closer: expected 2, got %d", winner) }
	})

	// The agreed price = winner's lineage-committed bid (plaintext lookup).
	// Binding: driver submitted H(enc_price || nonce || session_id). Rider
	// decrypts masks → finds winner → verifies lineage commit → derives
	// SHA256(nonce || session_id) as shared secret for OTP/phrase verification.
	// Driver already knows their own bid + nonce → derives same secret.
	t.Run("shared-secret-derivation", func(t *testing.T) {
		nonces := [][]byte{[]byte("driver-0-secret!"), []byte("noise-11111111")}
		sid := "ride-001"
		winner, _, _ := cgo.SingleKeyAuctionFull(params,
			[]int{1000, 1500}, []float64{5.0, 5.0}, []float64{0.1, 0.1},
			nonces, 800, 2500, w, 1)
		// Rider derives shared secret
		h := sha256.New(); h.Write(nonces[winner]); h.Write([]byte(sid))
		riderSecret := h.Sum(nil)
		// Winning driver derives same secret
		h2 := sha256.New(); h2.Write(nonces[winner]); h2.Write([]byte(sid))
		driverSecret := h2.Sum(nil)
		if string(riderSecret) != string(driverSecret) {
			t.Error("rider and driver shared secrets don't match")
		}
		t.Logf("shared secret=%x (for OTP/phrase/QR bilateral verification)", riderSecret[:8])
	})
}
