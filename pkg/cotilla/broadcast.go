package cotilla

import (
	"sync"
	"time"
)

// BroadcastEmitFunc builds and transmits one attempt of a broadcast with the given TTL and peer fanout.
type BroadcastEmitFunc func(ttl int, fanout int)

type broadcastJob struct {
	cancel chan struct{}
	once   sync.Once
}

func (j *broadcastJob) stop() {
	j.once.Do(func() { close(j.cancel) })
}

// ExpandingBroadcaster runs expanding-ring broadcasts that start with a short TTL and small fanout,
// doubling both TTL and peer fanout whenever no reply arrives within 2 * TTL * BroadcastHopTimeout.
type ExpandingBroadcaster struct {
	mu      sync.Mutex
	cfg     Config
	jobs    map[string]*broadcastJob
	stopped bool
}

// NewExpandingBroadcaster creates a scheduler bound to cfg.
func NewExpandingBroadcaster(cfg Config) *ExpandingBroadcaster {
	return &ExpandingBroadcaster{
		cfg:  cfg,
		jobs: make(map[string]*broadcastJob),
	}
}

// Start begins (or restarts) an expanding-ring broadcast for tag.
func (b *ExpandingBroadcaster) Start(tag string, maxTTL int, emit BroadcastEmitFunc) {
	if emit == nil || tag == "" {
		return
	}
	if maxTTL <= 0 {
		maxTTL = b.cfg.MaxBroadcastTTL
	}
	job := &broadcastJob{cancel: make(chan struct{})}

	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	if prev := b.jobs[tag]; prev != nil {
		prev.stop()
	}
	b.jobs[tag] = job
	b.mu.Unlock()

	go b.runLoop(tag, maxTTL, job, emit)
}

// MarkSatisfied cancels an in-flight expanding broadcast once a valid reply is received.
func (b *ExpandingBroadcaster) MarkSatisfied(tag string) {
	b.mu.Lock()
	job := b.jobs[tag]
	delete(b.jobs, tag)
	b.mu.Unlock()
	if job != nil {
		job.stop()
	}
}

// Stop cancels all active expanding-ring broadcasts.
func (b *ExpandingBroadcaster) Stop() {
	b.mu.Lock()
	b.stopped = true
	jobs := b.jobs
	b.jobs = make(map[string]*broadcastJob)
	b.mu.Unlock()
	for _, j := range jobs {
		j.stop()
	}
}

func (b *ExpandingBroadcaster) runLoop(tag string, maxTTL int, job *broadcastJob, emit BroadcastEmitFunc) {
	ttl := b.cfg.InitialBroadcastTTL
	fanout := b.cfg.InitialBroadcastFanout
	maxFanout := b.cfg.MaxPeers
	if maxFanout < fanout {
		maxFanout = fanout
	}

	for {
		emit(ttl, fanout)

		wait := b.retryDelay(ttl)
		timer := time.NewTimer(wait)
		select {
		case <-job.cancel:
			timer.Stop()
			return
		case <-timer.C:
		}

		nextTTL := ttl * 2
		if nextTTL > maxTTL {
			nextTTL = maxTTL
		}
		nextFanout := fanout * 2
		if nextFanout > maxFanout {
			nextFanout = maxFanout
		}
		if nextTTL == ttl && nextFanout == fanout {
			b.clearIfCurrent(tag, job)
			return
		}
		ttl = nextTTL
		fanout = nextFanout
	}
}

func (b *ExpandingBroadcaster) retryDelay(ttl int) time.Duration {
	unit := b.cfg.BroadcastHopTimeout
	if unit <= 0 {
		unit = 500 * time.Millisecond
	}
	if ttl < 1 {
		ttl = 1
	}
	return time.Duration(2*ttl) * unit
}

func (b *ExpandingBroadcaster) clearIfCurrent(tag string, job *broadcastJob) {
	b.mu.Lock()
	if b.jobs[tag] == job {
		delete(b.jobs, tag)
	}
	b.mu.Unlock()
}
