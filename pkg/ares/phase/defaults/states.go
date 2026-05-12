// Package defaults provides Phase implementations corresponding to the
// ARES v2.4 protocol specification phases (Phase 0a, 0b, 1a, 1b, 2, 3,
// G, G.2, D — see ARES_Protocol_Specification_v2_4.tex). Together they
// form the canonical session pipeline that an ARES application
// receives by calling NewARESDefaultRunner.
//
// Each spec phase owns one state-machine arc. Today's internal engine
// uses finer-grained sub-states (LOCKED → KEYGEN → GOSSIP); the
// framework abstraction folds keygen-internal accumulation into Phase
// 0a so the spec-phase mapping is 1:1 with state arcs. Phase
// implementations declare the WebSocket message types they consume
// and the SessionContext keys they read or produce; the SessionRunner
// validates this chain at construction time and derives the session
// state machine from the registered phase list.
//
// This file pins the SessionState labels used by the default phases.
// They match the labels in internal/engine/session.go for now so the
// follow-on logic port can wire one pipeline through the other
// without renaming. Application authors normally never reference
// these strings directly — they get a complete pipeline via
// NewARESDefaultRunner and override individual phases by swapping
// values into the runner's phase list.
package defaults

import "github.com/fheya/ares/pkg/ares/phase"

// SessionState labels for the canonical ARES pipeline. These match
// the existing internal/engine SessionState constants so the framework
// and the current hardcoded state machine refer to the same arcs.
const (
	StateInviting     phase.SessionState = "INVITING"
	StateLocked       phase.SessionState = "LOCKED"
	StateGossip       phase.SessionState = "GOSSIP"
	StateVerifying    phase.SessionState = "VERIFYING"
	StateSubmitting   phase.SessionState = "SUBMITTING"
	StateScoring      phase.SessionState = "SCORING"
	StateDecrypting   phase.SessionState = "DECRYPTING"
	StateBroadcasting phase.SessionState = "BROADCASTING"
	StateClosed       phase.SessionState = "CLOSED"
)

// SessionContext key names used to plumb state between default
// phases. App authors replacing a phase must produce keys with these
// names (or update the consuming phases to read different keys).
const (
	// CtxParticipants holds the ordered list of participant
	// pseudonyms for the session. Provided by Phase1a; consumed by
	// every later phase.
	CtxParticipants = "participants"

	// CtxCryptoContract holds the OpenFHE / CKKS parameter contract
	// (ring_dim, depth, scaling_mod_size, ...). Provided by Phase0a
	// or by an out-of-band CohortKeygenPhase; consumed by Phase1b,
	// Phase2, Phase3.
	CtxCryptoContract = "crypto_ctx"

	// CtxCollectivePublicKey holds the joint public key after
	// threshold keygen. Provided by Phase0a; consumed by Phase1b
	// (for encryption) and Phase2.
	CtxCollectivePublicKey = "collective_pk"

	// CtxSecretShares holds per-participant threshold secret key
	// shares. Provided by Phase0a; consumed by Phase3 for partial
	// decrypt and by Phase2 indirectly via eval keys.
	CtxSecretShares = "secret_shares"

	// CtxEvalKeys holds the collective evaluation keys (eval-mult,
	// eval-sum) needed for Phase2 homomorphic operations.
	// Provided by Phase0a; consumed by Phase2.
	CtxEvalKeys = "eval_keys"

	// CtxOnionRoundsComplete tracks gossip-phase progress.
	CtxOnionRoundsComplete = "onion_rounds_complete"

	// CtxContribHashes holds verified per-participant contribution
	// hashes from Phase G.2.
	CtxContribHashes = "contrib_hashes"

	// CtxMacSeeds holds per-participant MAC seeds gathered during
	// Phase G.2 and used to derive the session MAC key for Phase D.
	CtxMacSeeds = "mac_seeds"

	// CtxSessionMacKey holds the derived session MAC key (Phase G.2
	// → consumed by Phase D for message authentication).
	CtxSessionMacKey = "session_mac_key"

	// CtxEncryptedInputs holds the participant-submitted profile
	// ciphertexts and the initiator winner-package wrap. Provided
	// by Phase1b; consumed by Phase2.
	CtxEncryptedInputs = "encrypted_inputs"

	// CtxCipherWinnerPackage holds the FHE scorer's emitted
	// `ct_winner_pkg`. Provided by Phase2; consumed by Phase3.
	CtxCipherWinnerPackage = "ct_winner_pkg"

	// CtxWinnerPackage holds the decrypted, threshold-recovered
	// winner package. Provided by Phase3; consumed by Phase D
	// (which broadcasts it to all participants).
	CtxWinnerPackage = "winner_pkg"

	// CtxPhaseDSchedule holds the rate-limited per-participant
	// Phase D message-sending schedules. Provided by PhaseD on
	// entry; consumed by the PhaseD message handler.
	CtxPhaseDSchedule = "phased_schedule"
)
