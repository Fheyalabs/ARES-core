//go:build openfhe

package helperclient_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// TestArgmaxOverIPC drives argmax through the helper subprocess using
// keys built in-process via the cgo bridge. Isolates the
// helperclient IPC layer from any phase-wiring concerns.
func TestArgmaxOverIPC(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE smoke unavailable: %v", err)
	}
	binary := buildHelperBinary(t)
	defer os.Remove(binary)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := helperclient.Start(ctx, binary)
	if err != nil {
		t.Fatalf("helper start: %v", err)
	}
	defer client.Close()

	params := cgo.DefaultContractParams(4, 10)
	first, err := cgo.DistributedKeyGenFirst(params)
	if err != nil {
		t.Fatalf("keygen first: %v", err)
	}
	second, err := cgo.DistributedKeyGenNext(params, first.PublicKey)
	if err != nil {
		t.Fatalf("keygen next: %v", err)
	}

	evalMultKey, err := buildJointEvalMult(t, params, []cgo.DistributedKeyShare{first, second})
	if err != nil {
		t.Skipf("eval-mult chain unavailable: %v", err)
	}

	// Encrypt three scores.
	scores := []float64{0.5, -0.3, 0.0}
	cts := make([][]byte, len(scores))
	for i, s := range scores {
		ct, err := cgo.EncryptCKKSForContract(params, second.PublicKey, []float64{s, 0, 0, 0})
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		cts[i] = ct
	}

	hcParams := helperclient.ContractParams{
		RingDim:        params.RingDim,
		Depth:          params.Depth,
		ScalingModSize: 50,
	}
	masks, err := client.Argmax(hcParams, evalMultKey, cts, helperclient.ArgmaxParams{
		SharpeningPoly: helperclient.EvalPolyParams{
			Coefficients: []float64{0.5, 0.75, 0, -0.25},
			LowerBound:   -1, UpperBound: 1,
		},
	})
	if err != nil {
		t.Fatalf("argmax: %v", err)
	}
	if len(masks) != 3 {
		t.Fatalf("got %d masks, want 3", len(masks))
	}
}

func buildHelperBinary(t *testing.T) string {
	t.Helper()
	// helperclient/ is at pkg/ares/crypto/helperclient → root is ../../../..
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		root = filepath.Dir(root)
	}
	binary, err := os.CreateTemp("", "openfhe-helper-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	binary.Close()
	cmd := exec.Command("go", "build", "-tags", "openfhe",
		"-o", binary.Name(), "./cmd/openfhe-contract-helper")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(binary.Name())
		t.Skipf("build helper: %s", out)
	}
	return binary.Name()
}

func buildJointEvalMult(t *testing.T, params cgo.ContractParams, shares []cgo.DistributedKeyShare) ([]byte, error) {
	t.Helper()
	finalPK := shares[len(shares)-1].PublicKey
	lead, err := cgo.EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return nil, err
	}
	pks := make([][]byte, len(shares))
	mr1 := make([][]byte, len(shares))
	sr1 := make([][]byte, len(shares))
	pks[0], mr1[0], sr1[0] = shares[0].PublicKey, lead.EvalMultBase, lead.EvalSumBase
	for i := 1; i < len(shares); i++ {
		pks[i] = shares[i].PublicKey
		r1, err := cgo.EvalKeyRound1Participant(params, shares[i].SecretKeyShare,
			lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return nil, err
		}
		mr1[i] = r1.EvalMultSwitchShare
		sr1[i] = r1.EvalSumShare
	}
	combined, err := cgo.CombineEvalKeyRound1(params, pks, mr1, sr1)
	if err != nil {
		return nil, err
	}
	fs := make([][]byte, len(shares))
	for i := range shares {
		r2, err := cgo.EvalKeyRound2Participant(params, shares[i].SecretKeyShare,
			combined.EvalMultJoined, finalPK, shares[i].Lead)
		if err != nil {
			return nil, err
		}
		fs[i] = r2.EvalMultFinalShare
	}
	final, err := cgo.CombineEvalKeyRound2(params, finalPK, fs, combined.EvalSumFinal)
	if err != nil {
		return nil, err
	}
	return final.EvalMultFinal, nil
}
