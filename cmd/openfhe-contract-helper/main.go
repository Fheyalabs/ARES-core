//go:build openfhe

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	openfhe "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
)

type contractParamsJSON struct {
	RingDim        uint32  `json:"ring_dim"`
	ScalingFactor  float64 `json:"scaling_factor,omitempty"`
	ScalingModSize int     `json:"scaling_mod_size,omitempty"`
	Depth          uint32  `json:"depth"`
}

type request struct {
	Op             string             `json:"op"`
	Params         contractParamsJSON `json:"params"`
	PrevPublicKey  string             `json:"prev_public_key,omitempty"`
	JointPublicKey string             `json:"joint_public_key,omitempty"`
	OwnPublicKey   string             `json:"own_public_key,omitempty"`
	FinalPublicKey string             `json:"final_public_key,omitempty"`
	EvalMultBase   string             `json:"eval_mult_base,omitempty"`
	EvalSumBase    string             `json:"eval_sum_base,omitempty"`
	EvalMultJoined string             `json:"eval_mult_joined,omitempty"`
	Values         []float64          `json:"values,omitempty"`
	Ciphertext     string             `json:"ciphertext,omitempty"`
	SecretKeyShare string             `json:"secret_key_share,omitempty"`
	Lead           bool               `json:"lead,omitempty"`
	Partials       []string           `json:"partials,omitempty"`
	NSlots         int                `json:"n_slots,omitempty"`

	// Decomposable scoring primitives. See helperclient/scoring_ops.go.
	EvalKeys       string             `json:"eval_keys,omitempty"`
	CiphertextA    string             `json:"ciphertext_a,omitempty"`
	CiphertextB    string             `json:"ciphertext_b,omitempty"`
	Scalar         float64            `json:"scalar,omitempty"`
	Coefficients   []float64          `json:"coefficients,omitempty"`
	PolyLowerBound float64            `json:"poly_lower_bound,omitempty"`
	PolyUpperBound float64            `json:"poly_upper_bound,omitempty"`
	Ciphertexts    []string           `json:"ciphertexts,omitempty"`
}

type response struct {
	PublicKey          string    `json:"public_key,omitempty"`
	SecretKeyShare     string    `json:"secret_key_share,omitempty"`
	Lead               *bool     `json:"lead,omitempty"`
	Ciphertext         string    `json:"ciphertext,omitempty"`
	Partial            string    `json:"partial,omitempty"`
	Values             []float64 `json:"values,omitempty"`
	EvalMultBase       string    `json:"eval_mult_base,omitempty"`
	EvalSumBase        string    `json:"eval_sum_base,omitempty"`
	EvalMultShare      string    `json:"eval_mult_share,omitempty"`
	EvalSumShare       string    `json:"eval_sum_share,omitempty"`
	EvalMultFinalShare string    `json:"eval_mult_final_share,omitempty"`
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--daemon" {
			runDaemon()
			return
		}
	}

	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fail("decode request: %v", err)
	}
	res, err := run(req)
	if err != nil {
		fail("%v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fail("encode response: %v", err)
	}
}

// runDaemon reads newline-delimited JSON requests from stdin and writes
// envelope responses ({"result": ...} | {"error": "..."}) to stdout, one per
// line. Exits cleanly on EOF. Errors from individual ops are sent as
// envelopes; only protocol-level failures (bad JSON, write errors) terminate
// the process. Callers spawn one daemon per worker thread and reuse it across
// session calls to amortize OpenFHE library load and CryptoContext build.
func runDaemon() {
	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fail("decode request: %v", err)
		}
		envelope := struct {
			Result *response `json:"result,omitempty"`
			Error  string    `json:"error,omitempty"`
		}{}
		res, runErr := run(req)
		if runErr != nil {
			envelope.Error = runErr.Error()
		} else {
			envelope.Result = &res
		}
		if err := enc.Encode(envelope); err != nil {
			fail("encode response: %v", err)
		}
	}
}

func run(req request) (response, error) {
	params := req.Params.toContractParams()
	switch req.Op {
	case "keygen_first":
		share, err := openfhe.DistributedKeyGenFirst(params)
		if err != nil {
			return response{}, err
		}
		return keyShareResponse(share), nil
	case "keygen_next":
		prev, err := decodeB64("prev_public_key", req.PrevPublicKey)
		if err != nil {
			return response{}, err
		}
		share, err := openfhe.DistributedKeyGenNext(params, prev)
		if err != nil {
			return response{}, err
		}
		return keyShareResponse(share), nil
	case "encrypt_profile":
		joint, err := decodeB64("joint_public_key", req.JointPublicKey)
		if err != nil {
			return response{}, err
		}
		ct, err := openfhe.EncryptCKKSForContract(params, joint, req.Values)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(ct)}, nil
	case "evalkey_round1_lead":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		round1, err := openfhe.EvalKeyRound1Lead(params, sk)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultBase: encodeB64(round1.EvalMultBase),
			EvalSumBase:  encodeB64(round1.EvalSumBase),
		}, nil
	case "evalkey_round1_participant":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		multBase, err := decodeB64("eval_mult_base", req.EvalMultBase)
		if err != nil {
			return response{}, err
		}
		sumBase, err := decodeB64("eval_sum_base", req.EvalSumBase)
		if err != nil {
			return response{}, err
		}
		ownPK, err := decodeB64("own_public_key", req.OwnPublicKey)
		if err != nil {
			return response{}, err
		}
		round1, err := openfhe.EvalKeyRound1Participant(params, sk, multBase, sumBase, ownPK)
		if err != nil {
			return response{}, err
		}
		return response{
			EvalMultShare: encodeB64(round1.EvalMultSwitchShare),
			EvalSumShare:  encodeB64(round1.EvalSumShare),
		}, nil
	case "evalkey_round2_participant":
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		joined, err := decodeB64("eval_mult_joined", req.EvalMultJoined)
		if err != nil {
			return response{}, err
		}
		finalPK, err := decodeB64("final_public_key", req.FinalPublicKey)
		if err != nil {
			return response{}, err
		}
		round2, err := openfhe.EvalKeyRound2Participant(params, sk, joined, finalPK, req.Lead)
		if err != nil {
			return response{}, err
		}
		return response{EvalMultFinalShare: encodeB64(round2.EvalMultFinalShare)}, nil
	case "partial_decrypt":
		ct, err := decodeB64("ciphertext", req.Ciphertext)
		if err != nil {
			return response{}, err
		}
		sk, err := decodeB64("secret_key_share", req.SecretKeyShare)
		if err != nil {
			return response{}, err
		}
		partial, err := openfhe.PartialDecryptCKKSForContract(params, ct, sk, req.Lead)
		if err != nil {
			return response{}, err
		}
		return response{Partial: encodeB64(partial)}, nil
	case "fuse_partials":
		partials := make([][]byte, 0, len(req.Partials))
		for i, raw := range req.Partials {
			partial, err := decodeB64(fmt.Sprintf("partials[%d]", i), raw)
			if err != nil {
				return response{}, err
			}
			partials = append(partials, partial)
		}
		values, err := openfhe.FuseCKKSPartialsForContract(params, partials, req.NSlots)
		if err != nil {
			return response{}, err
		}
		return response{Values: values}, nil
	case "eval_poly":
		evalKeys, err := decodeB64("eval_keys", req.EvalKeys)
		if err != nil {
			return response{}, err
		}
		ct, err := decodeB64("ciphertext", req.Ciphertext)
		if err != nil {
			return response{}, err
		}
		if len(req.Coefficients) == 0 {
			return response{}, errors.New("eval_poly requires coefficients")
		}
		result, err := openfhe.EvalPolyCKKSForContract(params, evalKeys, ct, req.Coefficients)
		if err != nil {
			return response{}, err
		}
		return response{Ciphertext: encodeB64(result)}, nil
	case "eval_add", "eval_sub", "eval_mult", "eval_const_mult", "argmax":
		// Remaining decomposable primitives. Wrappers land in a
		// follow-up; Go-side API in helperclient is stable.
		return response{}, fmt.Errorf("op %q: not yet implemented (see helperclient/scoring_ops.go)", req.Op)
	default:
		return response{}, fmt.Errorf("unsupported op %q", req.Op)
	}
}

func (p contractParamsJSON) toContractParams() openfhe.ContractParams {
	scalingFactor := p.ScalingFactor
	if scalingFactor == 0 && p.ScalingModSize > 0 {
		scalingFactor = math.Ldexp(1, p.ScalingModSize)
	}
	return openfhe.ContractParams{
		RingDim:       p.RingDim,
		ScalingFactor: scalingFactor,
		Depth:         p.Depth,
	}
}

func keyShareResponse(share openfhe.DistributedKeyShare) response {
	lead := share.Lead
	return response{
		PublicKey:      encodeB64(share.PublicKey),
		SecretKeyShare: encodeB64(share.SecretKeyShare),
		Lead:           &lead,
	}
}

func decodeB64(field, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64: %w", field, err)
	}
	return out, nil
}

func encodeB64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
