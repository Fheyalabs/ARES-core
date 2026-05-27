// SPDX-License-Identifier: Apache-2.0

package lineage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestInMemoryStore_AppendGet_RoundTrip(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("x"), nil, signer)
	store := lineage.NewInMemoryStore()
	ctx := context.Background()

	if err := store.Append(ctx, node); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := store.Get(ctx, node.Hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hash != node.Hash {
		t.Errorf("Get returned hash %x, want %x", got.Hash, node.Hash)
	}
	if got.Role != node.Role {
		t.Errorf("Get returned role %q, want %q", got.Role, node.Role)
	}
}

func TestInMemoryStore_Append_Idempotent_OnIdenticalContent(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("x"), nil, signer)
	store := lineage.NewInMemoryStore()
	ctx := context.Background()

	if err := store.Append(ctx, node); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	err := store.Append(ctx, node)
	if !errors.Is(err, lineage.ErrNodeExists) {
		t.Fatalf("second Append: got %v, want ErrNodeExists", err)
	}
}

func TestInMemoryStore_Get_NotFound(t *testing.T) {
	store := lineage.NewInMemoryStore()
	ctx := context.Background()
	var missing lineage.NodeRef
	missing[0] = 0xff
	_, err := store.Get(ctx, missing)
	if !errors.Is(err, lineage.ErrNodeNotFound) {
		t.Fatalf("Get: got %v, want ErrNodeNotFound", err)
	}
}

func TestInMemoryStore_WalkSession_ReturnsAllNodesForSession(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	ctx := context.Background()

	n1, _ := lineage.Commit("sess-A", "p1", "r1", []byte("a"), nil, signer)
	n2, _ := lineage.Commit("sess-A", "p2", "r2", []byte("b"), nil, signer)
	n3, _ := lineage.Commit("sess-B", "p1", "r1", []byte("c"), nil, signer)
	_ = store.Append(ctx, n1)
	_ = store.Append(ctx, n2)
	_ = store.Append(ctx, n3)

	seen := map[lineage.NodeRef]bool{}
	for node, err := range store.WalkSession(ctx, "sess-A") {
		if err != nil {
			t.Fatalf("WalkSession yielded error: %v", err)
		}
		seen[node.Hash] = true
	}
	if !seen[n1.Hash] || !seen[n2.Hash] {
		t.Errorf("WalkSession sess-A missing nodes: %v", seen)
	}
	if seen[n3.Hash] {
		t.Errorf("WalkSession sess-A leaked node from sess-B")
	}
}

func TestInMemoryStore_Clear_RemovesOnlyNamedSession(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	ctx := context.Background()

	a, _ := lineage.Commit("sess-A", "p", "r", []byte("a"), nil, signer)
	b, _ := lineage.Commit("sess-B", "p", "r", []byte("b"), nil, signer)
	_ = store.Append(ctx, a)
	_ = store.Append(ctx, b)

	store.Clear("sess-A")

	if _, err := store.Get(ctx, a.Hash); !errors.Is(err, lineage.ErrNodeNotFound) {
		t.Errorf("after Clear(sess-A): sess-A node still present (err=%v)", err)
	}
	if _, err := store.Get(ctx, b.Hash); err != nil {
		t.Errorf("after Clear(sess-A): sess-B node disturbed: %v", err)
	}
}
