// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"sync"
	"time"
)

// ArtifactStore is an in-memory keyed blob cache. Applications use it to
// hold large CKKS payloads (collective public keys, eval-key bundles,
// score ciphertexts) that are too big to inline in WebSocket frames. The
// blob is uploaded via POST /artifacts/{key}, retrieved via GET
// /artifacts/{key}, and referenced by key in WS messages.
//
// Entries expire after TTL (default 30 minutes) on a periodic sweep. The
// store is concurrency-safe.
type ArtifactStore struct {
	mu      sync.RWMutex
	entries map[string]artifactEntry
	ttl     time.Duration
}

type artifactEntry struct {
	data    []byte
	expires time.Time
}

// NewArtifactStore returns a store with the default 30-minute TTL.
func NewArtifactStore() *ArtifactStore {
	return NewArtifactStoreWithTTL(30 * time.Minute)
}

// NewArtifactStoreWithTTL returns a store with a custom TTL.
func NewArtifactStoreWithTTL(ttl time.Duration) *ArtifactStore {
	s := &ArtifactStore{
		entries: make(map[string]artifactEntry),
		ttl:     ttl,
	}
	return s
}

// Put stores data under key, overwriting any prior value, and refreshes
// the TTL.
func (s *ArtifactStore) Put(key string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = artifactEntry{
		data:    append([]byte(nil), data...),
		expires: time.Now().Add(s.ttl),
	}
}

// Get returns the data under key. The boolean is false if the key is
// absent or expired.
func (s *ArtifactStore) Get(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		return nil, false
	}
	out := make([]byte, len(e.data))
	copy(out, e.data)
	return out, true
}

// Delete removes the entry for key (no-op if absent).
func (s *ArtifactStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

// Sweep purges expired entries. Callers may invoke it on a timer; the
// store does not start its own sweeper goroutine.
func (s *ArtifactStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	purged := 0
	for k, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, k)
			purged++
		}
	}
	return purged
}

// Resolve is the canonical accessor signature applications wire into
// scoring helpers ("give me the bytes behind this artifact key").
func (s *ArtifactStore) Resolve(key string) ([]byte, error) {
	if data, ok := s.Get(key); ok {
		return data, nil
	}
	return nil, fmt.Errorf("artifact %q not found", key)
}
