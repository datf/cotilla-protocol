// Package perfcheck provides Go 1.27 goroutineleak profiling, heap growth tracking,
// goroutine-count settle assertions, and overlay graph topology metrics for tests.
package perfcheck

import (
	"bytes"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"
)

// EnvInt returns the integer value of env var key, or def if unset or invalid.
func EnvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// ForceGC runs two GC cycles and yields briefly so finalizers and unreachable goroutines settle.
func ForceGC() {
	runtime.GC()
	runtime.Gosched()
	runtime.GC()
}

// AssertNoGoroutineLeaks uses Go 1.27's GA goroutineleak profile to detect any permanently
// blocked goroutines whose synchronization primitives are unreachable from live code.
func AssertNoGoroutineLeaks(t testing.TB) {
	t.Helper()
	ForceGC()
	time.Sleep(30 * time.Millisecond)
	ForceGC()

	prof := pprof.Lookup("goroutineleak")
	if prof == nil {
		t.Fatalf("perfcheck: Go 1.27 goroutineleak profile unavailable (runtime=%s)", runtime.Version())
	}
	if prof.Count() == 0 {
		return
	}
	var buf bytes.Buffer
	_ = prof.WriteTo(&buf, 2)
	t.Fatalf("perfcheck: detected %d leaked goroutine(s):\n%s", prof.Count(), buf.String())
}

// GoroutineBaseline captures the initial goroutine count before a test starts.
type GoroutineBaseline struct {
	Start int
}

// CaptureGoroutines records the current goroutine count after a brief settle.
func CaptureGoroutines() GoroutineBaseline {
	ForceGC()
	return GoroutineBaseline{Start: runtime.NumGoroutine()}
}

// AssertSettled polls until NumGoroutine() <= Start + maxDelta or fails on timeout.
func (b GoroutineBaseline) AssertSettled(t testing.TB, maxDelta int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	cur := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		ForceGC()
		cur = runtime.NumGoroutine()
		if cur <= b.Start+maxDelta {
			return cur
		}
		time.Sleep(50 * time.Millisecond)
	}
	var buf bytes.Buffer
	if p := pprof.Lookup("goroutine"); p != nil {
		_ = p.WriteTo(&buf, 1)
	}
	t.Fatalf("perfcheck: goroutines did not settle: start=%d current=%d (allowed delta=%d)\n%s",
		b.Start, cur, maxDelta, buf.String())
	return cur
}

// HeapSnapshot records live heap statistics after GC.
type HeapSnapshot struct {
	HeapAllocKB uint64
	HeapInuseKB uint64
	HeapObjects uint64
}

// TakeHeapSnapshot triggers GC and returns current heap metrics in KiB.
func TakeHeapSnapshot() HeapSnapshot {
	ForceGC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return HeapSnapshot{
		HeapAllocKB: ms.HeapAlloc / 1024,
		HeapInuseKB: ms.HeapInuse / 1024,
		HeapObjects: ms.HeapObjects,
	}
}

// GraphMetrics summarizes connected components and shortest-path hop distances.
type GraphMetrics struct {
	Nodes          int
	Edges          int
	Components     int
	GiantSize      int
	Diameter       int
	AvgPathLen     float64
	MinDegree      int
	MaxDegree      int
	AvgDegree      float64
	IsolatedNodes  int
}

// AnalyzeGraph computes connected components, giant component, exact diameter, and degree stats
// over an undirected adjacency map (if only directed edges exist, callers should symmetrize first
// or AnalyzeGraph will symmetrize automatically).
func AnalyzeGraph(adj map[string][]string) GraphMetrics {
	undir := make(map[string]map[string]bool, len(adj))
	for u := range adj {
		if undir[u] == nil {
			undir[u] = make(map[string]bool)
		}
	}
	for u, nbrs := range adj {
		for _, v := range nbrs {
			if u == v {
				continue
			}
			if undir[v] == nil {
				undir[v] = make(map[string]bool)
			}
			undir[u][v] = true
			undir[v][u] = true
		}
	}

	n := len(undir)
	if n == 0 {
		return GraphMetrics{}
	}

	m := GraphMetrics{Nodes: n, MinDegree: n}
	edgeSum := 0
	for _, nbrs := range undir {
		d := len(nbrs)
		edgeSum += d
		if d == 0 {
			m.IsolatedNodes++
		}
		if d < m.MinDegree {
			m.MinDegree = d
		}
		if d > m.MaxDegree {
			m.MaxDegree = d
		}
	}
	m.Edges = edgeSum / 2
	m.AvgDegree = float64(edgeSum) / float64(n)

	visited := make(map[string]bool, n)
	var totalDist, totalPairs int
	for root := range undir {
		if visited[root] {
			continue
		}
		m.Components++
		comp := bfsComponent(undir, root, visited)
		if len(comp) > m.GiantSize {
			m.GiantSize = len(comp)
		}
	}

	// Exact all-pairs shortest path over nodes for diameter and average hop distance.
	for src := range undir {
		dist := bfsDistances(undir, src)
		for dst, d := range dist {
			if dst == src {
				continue
			}
			if d > m.Diameter {
				m.Diameter = d
			}
			totalDist += d
			totalPairs++
		}
	}
	if totalPairs > 0 {
		m.AvgPathLen = float64(totalDist) / float64(totalPairs)
	}
	return m
}

func bfsComponent(undir map[string]map[string]bool, start string, visited map[string]bool) []string {
	queue := []string{start}
	visited[start] = true
	var comp []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		comp = append(comp, cur)
		for nxt := range undir[cur] {
			if !visited[nxt] {
				visited[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	return comp
}

func bfsDistances(undir map[string]map[string]bool, src string) map[string]int {
	dist := map[string]int{src: 0}
	queue := []string{src}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := dist[cur]
		for nxt := range undir[cur] {
			if _, ok := dist[nxt]; !ok {
				dist[nxt] = d + 1
				queue = append(queue, nxt)
			}
		}
	}
	return dist
}
