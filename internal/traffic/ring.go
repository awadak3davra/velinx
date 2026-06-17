// Package traffic keeps a rolling buffer of up/down samples and fans them out
// to subscribers (used by the SSE traffic stream that drives the live graph).
package traffic

import "sync"

// Sample is one second of throughput, in bytes per second, with a unix-ms timestamp.
type Sample struct {
	T    int64 `json:"t"`    // unix milliseconds
	Up   int64 `json:"up"`   // bytes/s uploaded
	Down int64 `json:"down"` // bytes/s downloaded
}

// Hub stores recent samples and broadcasts new ones to subscribers.
type Hub struct {
	mu   sync.Mutex
	buf  []Sample
	size int
	subs map[chan Sample]struct{}
}

// NewHub returns a Hub retaining up to size recent samples.
func NewHub(size int) *Hub {
	if size <= 0 {
		size = 300
	}
	return &Hub{
		size: size,
		buf:  make([]Sample, 0, size),
		subs: make(map[chan Sample]struct{}),
	}
}

// Push records a sample and broadcasts it to subscribers (non-blocking;
// samples are dropped for consumers that cannot keep up).
func (h *Hub) Push(s Sample) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buf) >= h.size {
		copy(h.buf, h.buf[1:])
		h.buf = h.buf[:h.size-1]
	}
	h.buf = append(h.buf, s)
	// Broadcast under the lock. The sends are non-blocking (buffered channel +
	// select default), so holding the lock can't deadlock — and it prevents a
	// subscriber's cancel() from closing a channel between our snapshot and the
	// send, which would panic with "send on closed channel".
	for ch := range h.subs {
		select {
		case ch <- s:
		default:
		}
	}
}

// Recent returns a copy of the retained samples, oldest first.
func (h *Hub) Recent() []Sample { return h.RecentN(0) }

// RecentN returns a copy of up to the last n retained samples, oldest first.
// n <= 0 returns all retained samples. The UI only renders the last ~90, so it
// asks for n=90 to avoid shipping the full 300-sample buffer every second.
func (h *Hub) RecentN(n int) []Sample {
	h.mu.Lock()
	defer h.mu.Unlock()
	start := 0
	if n > 0 && len(h.buf) > n {
		start = len(h.buf) - n
	}
	out := make([]Sample, len(h.buf)-start)
	copy(out, h.buf[start:])
	return out
}

// Subscribe returns a channel of future samples plus an unsubscribe func.
func (h *Hub) Subscribe() (<-chan Sample, func()) {
	ch := make(chan Sample, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, cancel
}
