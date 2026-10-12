// Copyright 2026 MobiFone ANM / Argus Sentinel integration
// SPDX-License-Identifier: Apache-2.0

package mlcheck

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults. Every knob is read from the environment once per process and is
// documented in README.md and services/argus-sidecar/README.md.
const (
	defaultSocketPath = "/run/argus/argus.sock"
	defaultTimeout    = 50 * time.Millisecond

	// Concurrency cap for in-flight RPCs. The Caddy process must not pile up
	// work for a slow sidecar: requests beyond the cap wait at most
	// queueWait, then fail open (counted as "overload").
	defaultMaxInflight = 64
	defaultQueueWait   = 5 * time.Millisecond

	// Circuit breaker: after this many consecutive RPC failures the circuit
	// opens for cooldown, during which calls fail open immediately
	// (counted as "circuit_open") while a single half-open probe is allowed
	// once the cooldown elapses.
	defaultCircuitFails    = 10
	defaultCircuitCooldown = 5 * time.Second

	// How often the aggregated counters are logged (one Info line on the
	// next evaluation after the interval). 0 disables the summary.
	defaultMetricsInterval = 60 * time.Second
)

type config struct {
	socketPath      string
	timeout         time.Duration
	maxInflight     int
	queueWait       time.Duration
	circuitFails    int
	circuitCooldown time.Duration
	metricsInterval time.Duration
}

var (
	cfgOnce sync.Once
	cfgVal  config
)

func getConfig() config {
	cfgOnce.Do(func() { cfgVal = loadConfig() })
	return cfgVal
}

func loadConfig() config {
	return config{
		socketPath:      envString("ARGUS_SOCKET", defaultSocketPath),
		timeout:         envDurationMS("ARGUS_TIMEOUT_MS", defaultTimeout),
		maxInflight:     envInt("ARGUS_MAX_INFLIGHT", defaultMaxInflight),
		queueWait:       time.Duration(envNonNegativeInt("ARGUS_QUEUE_WAIT_MS", int(defaultQueueWait/time.Millisecond))) * time.Millisecond,
		circuitFails:    envInt("ARGUS_CIRCUIT_FAILS", defaultCircuitFails),
		circuitCooldown: envDurationMS("ARGUS_CIRCUIT_COOLDOWN_MS", defaultCircuitCooldown),
		metricsInterval: envDurationSeconds("ARGUS_METRICS_INTERVAL_S", defaultMetricsInterval),
	}
}

// resetConfigForTests drops the cached configuration so tests can change the
// environment between runs.
func resetConfigForTests() {
	cfgOnce = sync.Once{}
}

func envString(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envDurationMS(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return def
}

func envDurationSeconds(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s >= 0 {
			return time.Duration(s) * time.Second
		}
	}
	return def
}

func envNonNegativeInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 60000 {
			return n
		}
	}
	return def
}
