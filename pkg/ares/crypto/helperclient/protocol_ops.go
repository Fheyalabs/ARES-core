package helperclient

// Protocol ops: the helper RPCs the existing Fheya smoke uses for
// threshold keygen, encryption, and partial-decryption.

// KeyShare is the result of one participant's contribution to the
// chained N-party threshold keygen. PublicKey is the (running) joint
// public key after this contribution; SecretKeyShare is this
// participant's share, retained client-side and used later in
// PartialDecrypt. Lead is true for the first participant.
type KeyShare struct {
	PublicKey      []byte
	SecretKeyShare []byte
	Lead           bool
}

// KeygenFirst is the first participant's contribution to keygen.
// Returns the bootstrap joint key plus the participant's share.
func (c *Client) KeygenFirst(params ContractParams) (KeyShare, error) {
	resp, err := c.call(Request{Op: "keygen_first", Params: params})
	if err != nil {
		return KeyShare{}, err
	}
	return decodeKeyShare(resp)
}

// KeygenNext extends the joint key with the next participant's share.
// prevPublicKey is the joint key emitted by the previous participant.
func (c *Client) KeygenNext(params ContractParams, prevPublicKey []byte) (KeyShare, error) {
	resp, err := c.call(Request{
		Op:            "keygen_next",
		Params:        params,
		PrevPublicKey: encodeB64(prevPublicKey),
	})
	if err != nil {
		return KeyShare{}, err
	}
	return decodeKeyShare(resp)
}

// EncryptProfile encrypts a float-valued vector under the joint
// public key. Used by participants to seal their inputs (bid amount,
// rating, profile vector, etc.).
func (c *Client) EncryptProfile(params ContractParams, jointPublicKey []byte, values []float64) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "encrypt_profile",
		Params:         params,
		JointPublicKey: encodeB64(jointPublicKey),
		Values:         values,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

// EvalKeyRound1Result is the lead's round-1 output: the bases that
// subsequent participants extend in round 1.
type EvalKeyRound1Result struct {
	EvalMultBase []byte
	EvalSumBase  []byte
}

// EvalKeyRound1Lead is the lead participant's round-1 contribution.
func (c *Client) EvalKeyRound1Lead(params ContractParams, secretKeyShare []byte) (EvalKeyRound1Result, error) {
	resp, err := c.call(Request{
		Op:             "evalkey_round1_lead",
		Params:         params,
		SecretKeyShare: encodeB64(secretKeyShare),
	})
	if err != nil {
		return EvalKeyRound1Result{}, err
	}
	multBase, err := decodeB64(resp.EvalMultBase)
	if err != nil {
		return EvalKeyRound1Result{}, err
	}
	sumBase, err := decodeB64(resp.EvalSumBase)
	if err != nil {
		return EvalKeyRound1Result{}, err
	}
	return EvalKeyRound1Result{EvalMultBase: multBase, EvalSumBase: sumBase}, nil
}

// EvalKeyRound1ParticipantShare is the per-participant output of
// round 1 (the share that gets fused into the joint eval-mult and
// eval-sum keys).
type EvalKeyRound1ParticipantShare struct {
	EvalMultShare []byte
	EvalSumShare  []byte
}

// EvalKeyRound1Participant is a non-lead participant's round-1
// contribution.
func (c *Client) EvalKeyRound1Participant(
	params ContractParams,
	secretKeyShare, evalMultBase, evalSumBase, ownPublicKey []byte,
) (EvalKeyRound1ParticipantShare, error) {
	resp, err := c.call(Request{
		Op:             "evalkey_round1_participant",
		Params:         params,
		SecretKeyShare: encodeB64(secretKeyShare),
		EvalMultBase:   encodeB64(evalMultBase),
		EvalSumBase:    encodeB64(evalSumBase),
		OwnPublicKey:   encodeB64(ownPublicKey),
	})
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	multShare, err := decodeB64(resp.EvalMultShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	sumShare, err := decodeB64(resp.EvalSumShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	return EvalKeyRound1ParticipantShare{EvalMultShare: multShare, EvalSumShare: sumShare}, nil
}

// EvalKeyRound2Participant is one participant's round-2 contribution.
func (c *Client) EvalKeyRound2Participant(
	params ContractParams,
	secretKeyShare, evalMultJoined, finalPublicKey []byte,
	lead bool,
) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "evalkey_round2_participant",
		Params:         params,
		SecretKeyShare: encodeB64(secretKeyShare),
		EvalMultJoined: encodeB64(evalMultJoined),
		FinalPublicKey: encodeB64(finalPublicKey),
		Lead:           lead,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.EvalMultFinalShare)
}

// PartialDecrypt produces one participant's partial decryption of a
// ciphertext.
func (c *Client) PartialDecrypt(
	params ContractParams,
	ciphertext, secretKeyShare []byte,
	lead bool,
) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "partial_decrypt",
		Params:         params,
		Ciphertext:     encodeB64(ciphertext),
		SecretKeyShare: encodeB64(secretKeyShare),
		Lead:           lead,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Partial)
}

// FusePartials combines participants' partial decryptions into the
// cleartext slot values.
func (c *Client) FusePartials(params ContractParams, partials [][]byte, nSlots int) ([]float64, error) {
	enc := make([]string, len(partials))
	for i, p := range partials {
		enc[i] = encodeB64(p)
	}
	resp, err := c.call(Request{
		Op:       "fuse_partials",
		Params:   params,
		Partials: enc,
		NSlots:   nSlots,
	})
	if err != nil {
		return nil, err
	}
	return resp.Values, nil
}

func decodeKeyShare(resp *Response) (KeyShare, error) {
	pk, err := decodeB64(resp.PublicKey)
	if err != nil {
		return KeyShare{}, err
	}
	sk, err := decodeB64(resp.SecretKeyShare)
	if err != nil {
		return KeyShare{}, err
	}
	lead := false
	if resp.Lead != nil {
		lead = *resp.Lead
	}
	return KeyShare{PublicKey: pk, SecretKeyShare: sk, Lead: lead}, nil
}
