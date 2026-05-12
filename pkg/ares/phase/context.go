package phase

import (
	"fmt"
	"sync"
)

// SessionContext is the typed bag of state shared across phases of one
// session run. Each phase declares which keys it reads (Requires) and
// produces (Provides) via ContextSchema; the runner verifies the
// declarations are satisfied before invoking the phase.
//
// SessionContext is concurrency-safe for use by phases that spawn
// goroutines internally. The runner itself drives one phase at a time
// for a given session, so cross-phase races are not expected — the
// lock here is defensive for in-phase parallelism (for example a
// keygen phase that fans out chunked artifact uploads).
type SessionContext struct {
	// SessionID identifies the session this context belongs to. It is
	// set once when the runner constructs the context and never
	// changes.
	SessionID string

	// CohortID, when non-empty, identifies the long-lived cohort
	// this session belongs to. Cohort-lifetime context entries are
	// indexed by this value at the runner-or-service level so that
	// many sessions can share them. An empty CohortID means the
	// session is one-off and per-cohort phases degrade to
	// per-session.
	CohortID string

	mu     sync.RWMutex
	values map[string]any
}

// NewSessionContext returns a SessionContext for the given session.
func NewSessionContext(sessionID string) *SessionContext {
	return &SessionContext{
		SessionID: sessionID,
		values:    make(map[string]any),
	}
}

// Get returns the value stored under key and a boolean indicating
// whether the key was present.
func (c *SessionContext) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.values[key]
	return v, ok
}

// Set stores value under key, overwriting any previous value. Phases
// should only Set keys they declared in their Provides schema.
func (c *SessionContext) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = value
}

// Has returns true if key has been set.
func (c *SessionContext) Has(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.values[key]
	return ok
}

// Keys returns a snapshot of the currently-set context keys, in no
// particular order. Useful for diagnostics and runner introspection.
func (c *SessionContext) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.values))
	for k := range c.values {
		out = append(out, k)
	}
	return out
}

// MustGet returns the value stored under key, or panics if the key is
// missing or the stored value does not assert to T. Phases that
// declared the key in their Requires schema can use MustGet because
// the runner refuses to start phases with unsatisfied requirements.
//
// Implemented as a free function rather than a method because Go does
// not allow parameterized methods.
func MustGet[T any](c *SessionContext, key string) T {
	v, ok := c.Get(key)
	if !ok {
		panic(fmt.Sprintf("phase: required context key %q is not set", key))
	}
	typed, ok := v.(T)
	if !ok {
		panic(fmt.Sprintf("phase: context key %q has type %T, expected %T", key, v, *new(T)))
	}
	return typed
}

// TryGet returns the typed value stored under key together with a
// boolean indicating whether the key was present and assignable to T.
func TryGet[T any](c *SessionContext, key string) (T, bool) {
	var zero T
	v, ok := c.Get(key)
	if !ok {
		return zero, false
	}
	typed, ok := v.(T)
	if !ok {
		return zero, false
	}
	return typed, true
}
