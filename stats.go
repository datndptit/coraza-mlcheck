// Copyright 2026 MobiFone ANM / Argus Sentinel integration
// SPDX-License-Identifier: Apache-2.0

package mlcheck

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/debuglog"
)

// reasonCode enumerates the machine-readable failure reasons written to
// TX:argus_error (and counted in the summary). "ok" is not a reason.
type reasonCode int

const (
	reasonClientInit reasonCode = iota
	reasonRPCError
	reasonRPCTimeout
	reasonInvalidResponse
	reasonOverload
	reasonCircuitOpen
	reasonDeadline
	reasonWrongPhase
	reasonBodyUnavailable
	reasonBodyRead
	reasonInvalidThreshold
	reasonInternal
	numReasons
)

// reasonNames is the wire/log form of each reasonCode; keep both in sync.
var reasonNames = [numReasons]string{
	"client_init",
	"rpc_error",
	"rpc_timeout",
	"invalid_response",
	"overload",
	"circuit_open",
	"deadline_exceeded",
	"wrong_phase",
	"body_reader_unavailable",
	"body_read_error",
	"invalid_threshold",
	"internal",
}

// Latency buckets (ms upper bounds); the last bucket is overflow. Recorded
// for every RPC attempt, so timeouts land in the overflow bucket and a
// stuck sidecar is visible in the summary.
var latBucketBoundsMS = [...]float64{0.5, 1, 2, 5, 10, 20, 50, 100, 200}

const numLatBuckets = len(latBucketBoundsMS) + 1

type statsCounters struct {
	calls       atomic.Uint64 // every mlcheck invocation
	dup         atomic.Uint64 // invocations suppressed by the one-RPC guard ("skipped")
	rpcAttempts atomic.Uint64 // RPCs actually sent
	ok          atomic.Uint64 // verdicts written
	failures    [numReasons]atomic.Uint64
	latency     [numLatBuckets]atomic.Uint64
	lastFlush   atomic.Int64 // unix nanos of the last summary log
}

var stats statsCounters

func recordCall() { stats.calls.Add(1) }

func recordDuplicate() { stats.dup.Add(1) }

func recordRPCAttempt() { stats.rpcAttempts.Add(1) }

func recordVerdict(d time.Duration) {
	stats.ok.Add(1)
	recordLatency(d)
}

func recordFailure(reason reasonCode, d time.Duration) {
	stats.failures[reason].Add(1)
	if d > 0 {
		recordLatency(d)
	}
}

func recordLatency(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	for i, bound := range latBucketBoundsMS {
		if ms <= bound {
			stats.latency[i].Add(1)
			return
		}
	}
	stats.latency[numLatBuckets-1].Add(1)
}

// StatsSnapshot is the counter set the summary is built from; exported for
// tests and for operators writing their own scrape tooling.
type StatsSnapshot struct {
	Calls       uint64
	Duplicates  uint64
	RPCAttempts uint64
	OK          uint64
	Failures    map[string]uint64
	// LatencyBuckets maps bucket label ("<=2ms", ">200ms") to cumulative
	// per-bucket counts.
	LatencyBuckets map[string]uint64
}

func SnapshotStats() StatsSnapshot {
	snap := StatsSnapshot{
		Calls:          stats.calls.Load(),
		Duplicates:     stats.dup.Load(),
		RPCAttempts:    stats.rpcAttempts.Load(),
		OK:             stats.ok.Load(),
		Failures:       map[string]uint64{},
		LatencyBuckets: map[string]uint64{},
	}
	for i, name := range reasonNames {
		if n := stats.failures[i].Load(); n > 0 {
			snap.Failures[name] = n
		}
	}
	for i := 0; i < numLatBuckets; i++ {
		if n := stats.latency[i].Load(); n > 0 {
			snap.LatencyBuckets[latBucketLabel(i)] = n
		}
	}
	return snap
}

func latBucketLabel(i int) string {
	if i < len(latBucketBoundsMS) {
		return "<=" + strconv.FormatFloat(latBucketBoundsMS[i], 'g', -1, 64) + "ms"
	}
	return ">" + strconv.FormatFloat(latBucketBoundsMS[len(latBucketBoundsMS)-1], 'g', -1, 64) + "ms"
}

// flushSummary logs one aggregated Info line per metricsInterval, lazily (on
// the next evaluation after the interval), so no background goroutine is
// needed. Failures are also logged per request at Debug level; the summary is
// the aggregated, alert-friendly view: evaluated/ok, skipped (duplicates),
// and failures by reason, plus the latency distribution of RPC attempts.
func flushSummary(log debuglog.Logger) {
	interval := getConfig().metricsInterval
	if interval <= 0 {
		return
	}
	now := time.Now()
	last := stats.lastFlush.Load()
	if last == 0 {
		stats.lastFlush.CompareAndSwap(0, now.UnixNano())
		return
	}
	if now.Sub(time.Unix(0, last)) < interval {
		return
	}
	if !stats.lastFlush.CompareAndSwap(last, now.UnixNano()) {
		return
	}

	ev := log.Info()
	if !ev.IsEnabled() {
		return
	}
	snap := SnapshotStats()
	var fails []string
	for i, name := range reasonNames {
		if n := stats.failures[i].Load(); n > 0 {
			fails = append(fails, fmt.Sprintf("%s=%d", name, n))
		}
	}
	failures := "none"
	if len(fails) > 0 {
		failures = strings.Join(fails, " ")
	}
	ev.Uint("calls", uint(snap.Calls)). //nolint:gosec // counter sizes fit
						Uint("ok", uint(snap.OK)).
						Uint("skipped_duplicate", uint(snap.Duplicates)).
						Uint("rpc_attempts", uint(snap.RPCAttempts)).
						Str("failures", failures).
						Str("latency_buckets", formatLatency(snap.LatencyBuckets)).
						Str("latency_quantiles", formatQuantiles()).
						Msg("mlcheck metrics summary")
}

func formatLatency(buckets map[string]uint64) string {
	if len(buckets) == 0 {
		return "n=0"
	}
	parts := make([]string, 0, len(buckets))
	for i := 0; i < numLatBuckets; i++ {
		label := latBucketLabel(i)
		if n, ok := buckets[label]; ok {
			parts = append(parts, fmt.Sprintf("%s:%d", label, n))
		}
	}
	return strings.Join(parts, ",")
}

// formatQuantiles approximates p50/p95/p99 from the bucket counters: the
// quantile is reported as the upper bound of the first bucket whose
// cumulative count reaches it.
func formatQuantiles() string {
	var total uint64
	for i := 0; i < numLatBuckets; i++ {
		total += stats.latency[i].Load()
	}
	if total == 0 {
		return "n=0"
	}
	quantile := func(q float64) string {
		target := uint64(float64(total) * q)
		var cum uint64
		for i := 0; i < numLatBuckets; i++ {
			cum += stats.latency[i].Load()
			if cum >= target && cum > 0 {
				if i < len(latBucketBoundsMS) {
					return "<=" + strconv.FormatFloat(latBucketBoundsMS[i], 'g', -1, 64)
				}
				return ">" + strconv.FormatFloat(latBucketBoundsMS[len(latBucketBoundsMS)-1], 'g', -1, 64)
			}
		}
		return "n/a"
	}
	return fmt.Sprintf("p50%s p95%s p99%s ms (n=%d)", quantile(0.50), quantile(0.95), quantile(0.99), total)
}
