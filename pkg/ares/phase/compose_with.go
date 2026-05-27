// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"errors"
	"fmt"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// ComposeWith constructs a lineage-enabled SessionRunner over the
// given phase list with the supplied options. Validates required
// options (WithSigner; WithPeerVerifiers for multi-party
// pipelines) fail-fast at construction time rather than at first
// verification attempt.
//
// Pipelines built with ComposeWith emit WSMessages at
// transport.WireProtocolVersionLineage ("2") with required
// Lineage fields. Pipelines built with the existing
// phase.Compose(...) function continue emitting v1 frames
// without Lineage (lineage-disabled backward-compatibility
// path).
//
// Default store (when WithStore is omitted):
// lineage.NewInMemoryStore().
func ComposeWith(phases []Phase, opts ...ComposeOption) (*SessionRunner, error) {
	o := &runnerOpts{}
	for _, opt := range opts {
		opt(o)
	}

	// Required: signer.
	if o.signer == nil {
		return nil, errors.New("phase: ComposeWith requires WithSigner")
	}

	// Required for multi-party: peer verifiers. A pipeline is
	// multi-party if any phase consumes WS messages from senders
	// other than the local party — detect by ConsumedMessageTypes
	// != nil on any phase.
	if needsPeers(phases) && len(o.peerVerifiers) == 0 {
		return nil, errors.New(
			"phase: ComposeWith requires WithPeerVerifiers for multi-party pipelines " +
				"(pipeline contains phases that consume WS messages)",
		)
	}

	// Default store.
	if o.store == nil {
		o.store = lineage.NewInMemoryStore()
	}

	// Verifier map: combine our own signer with peer verifiers so
	// self-produced commits also verify (a producer's own runner
	// re-verifies its own commits as a safety check).
	verifiers := map[string]sign.Signer{}
	for alg, v := range o.peerVerifiers {
		verifiers[alg] = v
	}
	if _, ok := verifiers[o.signer.Algorithm()]; !ok {
		verifiers[o.signer.Algorithm()] = o.signer
	}

	// Delegate to the existing Compose for phase-chain validation;
	// then attach lineage state.
	runner, err := Compose(phases...)
	if err != nil {
		return nil, fmt.Errorf("phase: ComposeWith: %w", err)
	}
	runner.attachLineage(o.store, o.signer, verifiers, o.failureHook)
	return runner, nil
}

// needsPeers returns true if any phase in phases consumes WS
// messages — implying multi-party communication.
func needsPeers(phases []Phase) bool {
	for _, p := range phases {
		if len(p.ConsumedMessageTypes()) > 0 {
			return true
		}
	}
	return false
}
