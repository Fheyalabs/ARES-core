// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import "testing"

func TestTuneUnionUsesMaxPairwiseDiffForRangeControl(t *testing.T) {
	_, tuned := TuneUnion(DistributionMetadata{
		MinMargin:       0.1,
		MedianMargin:    0.1,
		MaxMargin:       0.1,
		MaxPairwiseDiff: 1.0,
	}, []UnionComparator{{
		ID:         "narrow",
		Comparator: "logistic",
		Gain:       4,
		Bound:      1,
	}}, 4)

	if got := tuned[0].InputScale; got > 0.03 {
		t.Fatalf("InputScale %.6f ignores max pairwise range; want <= 0.03", got)
	}
}

func TestTuneUnionPreservesPerComparatorRangeMargins(t *testing.T) {
	_, tuned := TuneUnion(DistributionMetadata{
		MinMargin:       0.1,
		MedianMargin:    0.1,
		MaxMargin:       0.1,
		MaxPairwiseDiff: 1.0,
	}, []UnionComparator{
		{ID: "close", Comparator: "logistic", Gain: 4, Bound: 3, RangeMargin: 0.1},
		{ID: "wide", Comparator: "logistic", Gain: 3, Bound: 6, RangeMargin: 1.0},
	}, 4)

	if !(tuned[0].InputScale > tuned[1].InputScale) {
		t.Fatalf("close comparator scale %.6f must exceed wide comparator scale %.6f", tuned[0].InputScale, tuned[1].InputScale)
	}
}
