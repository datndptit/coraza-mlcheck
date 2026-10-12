// Copyright 2026 MobiFone ANM / Argus Sentinel integration
// SPDX-License-Identifier: Apache-2.0

package mlcheck

import (
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/debuglog"
)

// socketState bundles the per-socket runtime guards: a concurrency limiter
// and a circuit breaker. One sidecar socket per Caddy node is the deployed
// shape, but the state is keyed by path so per-rule socket overrides (e.g.
// a mock during testing) get their own guards.
type socketState struct {
	limiter *limiter
	breaker *breaker
}

var (
	statesMu sync.Mutex
	states   = map[string]*socketState{}
)

func stateFor(socketPath string) *socketState {
	statesMu.Lock()
	defer statesMu.Unlock()
	if st, ok := states[socketPath]; ok {
		return st
	}
	cfg := getConfig()
	st := &socketState{
		limiter: newLimiter(cfg.maxInflight),
		breaker: newBreaker(cfg.circuitFails, cfg.circuitCooldown),
	}
	states[socketPath] = st
	return st
}

// limiter bounds concurrent RPCs with a buffered-channel semaphore. A full
// limiter means the sidecar is slower than the offered load; the caller waits
// at most queueWait (never past its deadline) and then fails open instead of
// growing an unbounded queue inside Caddy.
type limiter struct {
	sem chan struct{}
}

func newLimiter(maxInflight int) *limiter {
	if maxInflight < 1 {
		maxInflight = 1
	}
	return &limiter{sem: make(chan struct{}, maxInflight)}
}

// acquire takes a slot, waiting up to wait (bounded by deadline). It returns
// false when no slot became free in time.
func (l *limiter) acquire(deadline time.Time, wait time.Duration) bool {
	select {
	case l.sem <- struct{}{}:
		return true
	default:
	}
	if wait <= 0 {
		return false
	}
	if remaining := time.Until(deadline); remaining < wait {
		wait = remaining
	}
	if wait <= 0 {
		return false
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case l.sem <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

func (l *limiter) release() {
	select {
	case <-l.sem:
	default:
	}
}

type breakerState int

const (
	breakerClosed breakerState = iota
	breakerOpen
	breakerHalfOpen
)

type breaker struct {
	mu                 sync.Mutex
	fails, failsToOpen int
	cooldown           time.Duration
	state              breakerState
	openedAt           time.Time
	generation         uint64
}

// A permit belongs to a breaker generation. Late responses from an earlier
// generation cannot close a newly opened circuit or resolve its recovery probe.
type breakerPermit struct {
	breaker    *breaker
	generation uint64
	once       sync.Once
}

func newBreaker(failsToOpen int, cooldown time.Duration) *breaker {
	if failsToOpen < 1 {
		failsToOpen = 1
	}
	if cooldown <= 0 {
		cooldown = time.Second
	}
	return &breaker{failsToOpen: failsToOpen, cooldown: cooldown}
}

func (b *breaker) acquire(now time.Time) *breakerPermit {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == breakerHalfOpen {
		return nil
	}
	if b.state == breakerOpen {
		if now.Sub(b.openedAt) < b.cooldown {
			return nil
		}
		b.state = breakerHalfOpen
		b.generation++
	}
	return &breakerPermit{breaker: b, generation: b.generation}
}

func (p *breakerPermit) success(log debuglog.Logger)                { p.finish(true, time.Now(), log) }
func (p *breakerPermit) failure(now time.Time, log debuglog.Logger) { p.finish(false, now, log) }
func (p *breakerPermit) finish(ok bool, now time.Time, log debuglog.Logger) {
	p.once.Do(func() {
		b := p.breaker
		b.mu.Lock()
		if p.generation != b.generation {
			b.mu.Unlock()
			return
		}
		message := ""
		if ok {
			if b.state == breakerHalfOpen {
				message = "mlcheck: circuit breaker closed (sidecar recovered)"
				b.generation++
			}
			b.state = breakerClosed
			b.fails = 0
		} else {
			b.fails++
			if b.state == breakerHalfOpen || b.fails >= b.failsToOpen {
				b.state = breakerOpen
				b.openedAt = now
				b.generation++
				message = "mlcheck: circuit breaker open (sidecar failing, failing open)"
			}
		}
		b.mu.Unlock()
		if message != "" {
			logInfo(log, message)
		}
	})
}

func logInfo(log debuglog.Logger, msg string) {
	if ev := log.Info(); ev.IsEnabled() {
		ev.Msg(msg)
	}
}
