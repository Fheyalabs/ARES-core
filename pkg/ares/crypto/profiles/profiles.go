// SPDX-License-Identifier: Apache-2.0

// Package profiles defines named, reproducible crypto parameter profiles.
//
// Profiles are additive presets for callers that want a known-good baseline.
// They do not replace the lower-level configurable CKKS/BFV APIs.
package profiles

type Scheme string

const (
	SchemeCKKS Scheme = "ckks"
	SchemeBFV  Scheme = "bfv"
)

type ProcessParallelism string

const (
	ParallelismDisabled ProcessParallelism = "disabled"
	ParallelismBounded  ProcessParallelism = "bounded"
)

type CKKSUnionProfile struct {
	Name             string
	Scheme           Scheme
	RingDim          uint32
	Depth            uint32
	ScalingModSize   int
	ProfileDim       int
	PayloadSlotCount int
	Comparators      []CKKSComparator
	Parallel         CKKSParallel
}

type CKKSComparator struct {
	ID                   string
	Comparator           string
	SharpenSelector      bool
	SelectorSchedule     string
	ComparatorGain       float64
	ComparatorBound      float64
	ComparatorDegree     int
	ComparatorInputScale float64
}

type CKKSParallel struct {
	ComparatorWorkers   int
	OMPThreadsPerWorker int
}

type BFVBlindProfile struct {
	Name                string
	Scheme              Scheme
	RingDim             uint32
	MultiplicativeDepth uint32
	PlaintextModulus    uint64
	BatchSize           int
	ProfileDim          int
	PackageBytes        int
	QuantizationScale   int
	StepPolyBits        int
	ProcessParallelism  ProcessParallelism
}

func CKKSRing32KUnionV1() CKKSUnionProfile {
	return CKKSUnionProfile{
		Name:             "ckks_ring32k_union_v1",
		Scheme:           SchemeCKKS,
		RingDim:          32768,
		Depth:            16,
		ScalingModSize:   35,
		ProfileDim:       128,
		PayloadSlotCount: 640,
		Comparators: []CKKSComparator{
			{
				ID:               "ss5",
				Comparator:       "selector",
				SharpenSelector:  true,
				SelectorSchedule: "smoothstep5",
			},
			{
				ID:               "logi_g4_b3_d13",
				Comparator:       "logistic",
				ComparatorGain:   4,
				ComparatorBound:  3,
				ComparatorDegree: 13,
			},
			{
				ID:               "logi_g3_b6_d13",
				Comparator:       "logistic",
				ComparatorGain:   3,
				ComparatorBound:  6,
				ComparatorDegree: 13,
			},
		},
		Parallel: CKKSParallel{
			ComparatorWorkers:   3,
			OMPThreadsPerWorker: 3,
		},
	}
}

func BFVRing32KBlindV1() BFVBlindProfile {
	return BFVBlindProfile{
		Name:                "bfv_ring32k_blind_v1",
		Scheme:              SchemeBFV,
		RingDim:             32768,
		MultiplicativeDepth: 20,
		PlaintextModulus:    65537,
		BatchSize:           128,
		ProfileDim:          128,
		PackageBytes:        80,
		QuantizationScale:   63,
		StepPolyBits:        13,
		ProcessParallelism:  ParallelismDisabled,
	}
}

func BFVLightBlindV1() BFVBlindProfile {
	return BFVBlindProfile{
		Name:                "bfv_light_blind_v1",
		Scheme:              SchemeBFV,
		RingDim:             8192,
		MultiplicativeDepth: 10,
		PlaintextModulus:    65537,
		BatchSize:           32,
		ProfileDim:          8,
		PackageBytes:        16,
		QuantizationScale:   15,
		StepPolyBits:        6,
		ProcessParallelism:  ParallelismDisabled,
	}
}
