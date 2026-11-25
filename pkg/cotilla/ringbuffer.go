package cotilla

import (
	"sync"
	"time"
)

// RingBuffer stores recent ephemeral envelopes in memory for catch-up and reconnect recovery.
type RingBuffer struct {
	mu       sync.RWMutex
	capacity int
	ttl      time.Duration
	items    []*Envelope
}

// NewRingBuffer creates a thread-safe ring buffer with the given capacity and message TTL.
func NewRingBuffer(capacity int, ttl time.Duration) *RingBuffer {
	if capacity <= 0 {
		capacity = 50
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &RingBuffer{
		capacity: capacity,
		ttl:      ttl,
		items:    make([]*Envelope, 0, capacity),
	}
}

// Push adds an envelope to the ring buffer, evicting expired items or the oldest items when full.
func (rb *RingBuffer) Push(env *Envelope) {
	if env == nil {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.pruneLocked()

	// Check if already present to avoid duplicates
	envID := env.ID()
	for _, item := range rb.items {
		if item.ID() == envID {
			return
		}
	}

	if len(rb.items) >= rb.capacity {
		// Shift in-place and clear tail so evicted *Envelope pointers can be GC'd.
		copy(rb.items, rb.items[1:])
		rb.items[len(rb.items)-1] = env
		return
	}
	rb.items = append(rb.items, env)
}

// pruneLocked removes entries older than the configured TTL. Must be called while holding mu.
func (rb *RingBuffer) pruneLocked() {
	if rb.ttl <= 0 {
		return
	}
	cutoff := time.Now().Add(-rb.ttl).UnixMilli()
	n := 0
	for _, item := range rb.items {
		if item.Timestamp >= cutoff {
			rb.items[n] = item
			n++
		}
	}
	clear(rb.items[n:])
	rb.items = rb.items[:n]
}

// GetMissing returns all unexpired envelopes that are not present in knownIDs.
// If lastSeenID is non-empty and found, only envelopes occurring after lastSeenID are considered.
func (rb *RingBuffer) GetMissing(lastSeenID string, knownIDs []string) []*Envelope {
	return rb.GetMissingForEpochRange(lastSeenID, knownIDs, 0, 0)
}

// GetMissingForEpochRange returns all unexpired envelopes not present in knownIDs within the specified epoch bounds.
// If minEpoch > 0, envelopes with EpochID < minEpoch are excluded (enforcing Pre-Join Forward Secrecy).
// If maxEpoch > 0, envelopes with EpochID > maxEpoch are excluded (enforcing Post-Eviction Confidentiality).
func (rb *RingBuffer) GetMissingForEpochRange(lastSeenID string, knownIDs []string, minEpoch, maxEpoch int64) []*Envelope {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	cutoff := time.Now().Add(-rb.ttl).UnixMilli()
	knownSet := make(map[string]struct{}, len(knownIDs))
	for _, id := range knownIDs {
		knownSet[id] = struct{}{}
	}

	startIndex := 0
	if lastSeenID != "" {
		for i, item := range rb.items {
			if item.ID() == lastSeenID {
				startIndex = i + 1
				break
			}
		}
	}

	var missing []*Envelope
	for i := startIndex; i < len(rb.items); i++ {
		item := rb.items[i]
		if item.Timestamp < cutoff {
			continue
		}
		if minEpoch > 0 && item.EpochID < minEpoch {
			continue
		}
		if maxEpoch > 0 && item.EpochID > maxEpoch {
			continue
		}
		if _, known := knownSet[item.ID()]; !known {
			missing = append(missing, item)
		}
	}
	return missing
}

// All returns a copy of all current unexpired envelopes in the ring buffer.
func (rb *RingBuffer) All() []*Envelope {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	cutoff := time.Now().Add(-rb.ttl).UnixMilli()
	out := make([]*Envelope, 0, len(rb.items))
	for _, item := range rb.items {
		if item.Timestamp >= cutoff {
			out = append(out, item)
		}
	}
	return out
}

// Len returns the number of active items in the ring buffer.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return len(rb.items)
}
