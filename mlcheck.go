// Copyright 2026 MobiFone ANM / Argus Sentinel integration
// SPDX-License-Identifier: Apache-2.0

// Package mlcheck registers the "mlcheck" Coraza action. The action hands the
// current HTTP request to the Argus Sentinel v4 ML classifier over a Unix
// Domain Socket (gRPC) and stores the verdict in transaction-scoped TX
// variables that later SecLang rules act on.
//
// The v4 model is a binary clean/attack classifier: the wire response carries
// a single probability (attack_prob -> risk_score) and at most the "attack"
// detection label. See proto/argusv1/argus.proto for the contract and
// services/argus-sidecar for the server side.
//
// SecLang usage:
//
//	# Phase 2 is mandatory: the request body buffer is only populated once
//	# ProcessRequestBody runs.
//	SecRule REQUEST_URI "@unconditionalMatch" \
//	    "id:9000,phase:2,pass,nolog,noauditlog,mlcheck"
//
//	# Optional: override the socket path on the rule line.
//	SecRule REQUEST_URI "@unconditionalMatch" \
//	    "id:9001,phase:2,pass,nolog,noauditlog,mlcheck:/run/argus/argus.sock"
//
//	# Downstream rules read the verdict from TX (note: @gt on a decimal
//	# never matches â€” Rule IDs cannot compare floats; the action does).
//	SecRule TX:argus_is_clean "@streq 0" \
//	    "id:9100,phase:2,deny,status:403,log,msg:'Argus blocked: prob=%{tx.argus_risk_score}'"
//
// TX variables written:
//
//	argus_is_clean         "0" attack verdict, "1" clean verdict,
//	                       "" no verdict (fail-open; "@streq 0" stays inert)
//	argus_risk_score       attack_prob, full precision, only with a verdict
//	argus_detections       "attack" when flagged, "" otherwise
//	argus_detection_attack attack_prob when flagged (per-label variable kept
//	                       from the pre-v4 contract; v4 has one label)
//	argus_status           "ok" | "error": outcome of the evaluation that ran
//	argus_error            "" on success, machine-readable reason on failure
//	argus_skip             "duplicate" when this invocation was suppressed by
//	                       the one-RPC-per-transaction guard
//
// TX variable read (optional input):
//
//	argus_threshold        A float in [0,1]. When set and valid, the action
//	                       computes the verdict as attack_prob > threshold
//	                       instead of trusting the sidecar verdict, and keeps
//	                       argus_is_clean / argus_detections consistent with
//	                       it. An invalid value fails open with
//	                       argus_error=invalid_threshold and no RPC.
//
// Fail-open policy: any failure (sidecar down, timeout, overload, circuit
// open, wrong phase, unavailable body, invalid threshold) leaves
// argus_is_clean empty so rules matching "@streq 0" never fire, while
// argus_status/argus_error record what happened. Failures are never counted
// as model-confirmed clean.
package mlcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	argusv1 "github.com/datndptit/coraza-mlcheck/proto/argusv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Body sent to the sidecar is capped here. The v4 preprocessing consumes at
// most the first 512 characters of the body after normalization; 4 KiB is
// generous and bounds the gRPC payload regardless of SecRequestBodyLimit
// (this is NOT a request-body limit for Coraza).
const maxBodyBytes = 4096

// TX variable names. Kept in one block: the operational rule templates in
// examples/ and documentation reference these exact names.
const (
	txIsClean      = "argus_is_clean"
	txRiskScore    = "argus_risk_score"
	txDetections   = "argus_detections"
	txDetectionPfx = "argus_detection_"
	txStatus       = "argus_status"
	txError        = "argus_error"
	txSkip         = "argus_skip"
	txThreshold    = "argus_threshold"

	// v4 has a single detection label.
	labelAttack = "attack"

	statusOK    = "ok"
	statusError = "error"

	skipDuplicate = "duplicate"
)

var errInvalidArg = errors.New("mlcheck: argument must be an absolute socket path, e.g. mlcheck:/run/argus/argus.sock")

func init() {
	plugins.RegisterAction("mlcheck", func() plugintypes.Action {
		return &mlcheckFn{}
	})
}

type mlcheckFn struct {
	socketPath string
}

func (a *mlcheckFn) Init(_ plugintypes.RuleMetadata, data string) error {
	data = strings.TrimSpace(data)
	if data == "" {
		a.socketPath = getConfig().socketPath
		return nil
	}
	if !strings.HasPrefix(data, "/") {
		return errInvalidArg
	}
	a.socketPath = data
	return nil
}

func (a *mlcheckFn) Evaluate(_ plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	log := tx.DebugLogger()
	txVars := tx.Variables().TX()

	recordCall()

	// Last-resort fail-open: an unexpected panic inside the action must not
	// take down request processing. The verdict variables are left without a
	// score, exactly like any other error path.
	defer func() {
		if r := recover(); r != nil {
			txVars.Set(txIsClean, []string{""})
			txVars.Set(txDetections, []string{""})
			txVars.Set(txRiskScore, []string{""})
			txVars.Set(txDetectionPfx+labelAttack, []string{""})
			txVars.Set(txStatus, []string{statusError})
			txVars.Set(txError, []string{reasonNames[reasonInternal]})
			recordFailure(reasonInternal, 0)
			if ev := log.Error(); ev.IsEnabled() {
				ev.Str("tx_id", tx.ID()).Str("panic", fmt.Sprint(r)).Msg("mlcheck: internal error (fail-open)")
			}
		}
	}()

	// One evaluation per transaction: a second mlcheck hit (for example a
	// global rule merged with a host rule) is suppressed so the sidecar sees
	// one RPC and the first verdict is never overwritten.
	if firstValue(txVars.Get(txStatus)) != "" {
		txVars.Set(txSkip, []string{skipDuplicate})
		recordDuplicate()
		if ev := log.Debug(); ev.IsEnabled() {
			ev.Str("tx_id", tx.ID()).Msg("mlcheck: duplicate invocation suppressed")
		}
		return
	}

	start := time.Now()
	defer flushSummary(log)

	// Rules running before phase 2 have no request body buffered yet; an
	// earlier invocation would silently classify an empty body.
	if tx.LastPhase() < corazatypes.PhaseRequestBody {
		a.fail(txVars, log, tx.ID(), start, reasonWrongPhase, nil)
		return
	}

	body, err := readRawBody(tx)
	if err != nil {
		reason := reasonBodyRead
		if errors.Is(err, errNoBodyReader) {
			reason = reasonBodyUnavailable
		}
		a.fail(txVars, log, tx.ID(), start, reason, err)
		return
	}

	// Optional per-rule threshold. Parsed BEFORE the RPC: an invalid value
	// must fail open without silently falling back to another threshold.
	threshold, useThreshold, thresholdOK := thresholdFromTX(txVars)
	if !thresholdOK {
		a.fail(txVars, log, tx.ID(), start, reasonInvalidThreshold,
			fmt.Errorf("TX:%s is not a finite float in [0,1]", txThreshold))
		return
	}

	cfg := getConfig()
	deadline := start.Add(cfg.timeout)
	if !time.Now().Before(deadline) {
		// The budget was already gone before any work was queued.
		a.fail(txVars, log, tx.ID(), start, reasonDeadline, nil)
		return
	}

	st := stateFor(a.socketPath)
	permit := st.breaker.acquire(time.Now())
	if permit == nil {
		a.fail(txVars, log, tx.ID(), start, reasonCircuitOpen, nil)
		return
	}

	// A permit resolves exactly once, including on a recovered panic.
	defer func() { permit.failure(time.Now(), log) }()
	if !st.limiter.acquire(deadline, cfg.queueWait) {
		permit.failure(time.Now(), log)
		a.fail(txVars, log, tx.ID(), start, reasonOverload, nil)
		return
	}
	defer st.limiter.release()

	client, err := getClient(a.socketPath)
	if err != nil {
		permit.failure(time.Now(), log)
		a.fail(txVars, log, tx.ID(), start, reasonClientInit, err)
		return
	}

	req := &argusv1.ClassifyRequest{
		Method:  tx.Variables().RequestMethod().Get(),
		Uri:     requestURI(tx.Variables()),
		Headers: collectHeaders(tx.Variables()),
		Body:    body,
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	recordRPCAttempt()
	resp, err := client.Classify(ctx, req)
	if err != nil {
		reason := reasonRPCError
		if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
			reason = reasonRPCTimeout
		}
		permit.failure(time.Now(), log)
		a.fail(txVars, log, tx.ID(), start, reason, err)
		return
	}

	if resp == nil {
		permit.failure(time.Now(), log)
		a.fail(txVars, log, tx.ID(), start, reasonInvalidResponse, nil)
		return
	}
	p := resp.GetRiskScore()
	if math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 1 {
		permit.failure(time.Now(), log)
		a.fail(txVars, log, tx.ID(), start, reasonInvalidResponse,
			fmt.Errorf("attack_prob out of range: %v", p))
		return
	}
	permit.success(log)

	isAttack := !resp.GetIsClean()
	source := "sidecar"
	if useThreshold {
		isAttack = p > threshold
		source = "tx_threshold"
	}
	writeVerdict(txVars, p, isAttack)
	recordVerdict(time.Since(start))

	if ev := log.Debug(); ev.IsEnabled() {
		ev.Str("tx_id", tx.ID()).
			Str("socket", a.socketPath).
			Bool("is_attack", isAttack).
			Str("attack_prob", formatScore(p)).
			Str("verdict_source", source).
			Msg("mlcheck: verdict received")
	}
}

func (a *mlcheckFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

// fail records a failed evaluation. It deliberately does NOT write a clean
// verdict: traffic keeps flowing because no rule can match "0" in
// argus_is_clean, and error/timeout statistics never count as model-confirmed
// clean. Rules on TX:argus_error can alert on the failure.
func (a *mlcheckFn) fail(txVars collection.Map, log debuglog.Logger, txID string, start time.Time, reason reasonCode, err error) {
	txVars.Set(txIsClean, []string{""})
	txVars.Set(txDetections, []string{""})
	txVars.Set(txRiskScore, []string{""})
	txVars.Set(txDetectionPfx+labelAttack, []string{""})
	txVars.Set(txStatus, []string{statusError})
	txVars.Set(txError, []string{reasonNames[reason]})
	recordFailure(reason, time.Since(start))

	if ev := log.Debug(); ev.IsEnabled() {
		ev = ev.Str("tx_id", txID).Str("reason", reasonNames[reason]).Str("socket", a.socketPath)
		if err != nil {
			ev = ev.Err(err)
		}
		ev.Msg("mlcheck: no verdict (fail-open)")
	}
}

func writeVerdict(txVars collection.Map, p float64, isAttack bool) {
	score := formatScore(p)
	if isAttack {
		txVars.Set(txIsClean, []string{"0"})
		txVars.Set(txDetections, []string{labelAttack})
		txVars.Set(txDetectionPfx+labelAttack, []string{score})
	} else {
		txVars.Set(txIsClean, []string{"1"})
		txVars.Set(txDetections, []string{""})
		txVars.Set(txDetectionPfx+labelAttack, []string{""})
	}
	txVars.Set(txRiskScore, []string{score})
	txVars.Set(txStatus, []string{statusOK})
	txVars.Set(txError, []string{""})
	txVars.Set(txSkip, []string{""})
}

func formatScore(p float64) string {
	// Full precision (shortest round-trip decimal, no exponent), so log
	// consumers can compare against thresholds like 0.998175 exactly.
	return strconv.FormatFloat(p, 'f', -1, 64)
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

// requestURI prefers REQUEST_URI_RAW (the request line as sent, absolute-form
// kept); the v4 preprocessing strips scheme://host itself.
func requestURI(v plugintypes.TransactionVariables) string {
	if raw := v.RequestURIRaw().Get(); raw != "" {
		return raw
	}
	return v.RequestURI().Get()
}

// collectHeaders builds the header map for the sidecar: only the headers the
// v4 preprocessing consumes, lower-cased names, and duplicate values of one
// header joined with "; " in the order Coraza saw them. Authorization and
// every other header are deliberately excluded.
func collectHeaders(v plugintypes.TransactionVariables) map[string]string {
	out := make(map[string]string, 3)
	for _, md := range v.RequestHeaders().FindAll() {
		name := strings.ToLower(strings.TrimSpace(md.Key()))
		switch name {
		case "user-agent", "referer", "cookie":
		default:
			continue
		}
		if prev, ok := out[name]; ok {
			out[name] = prev + "; " + md.Value()
		} else {
			out[name] = md.Value()
		}
	}
	return out
}

var errNoBodyReader = errors.New("transaction does not expose RequestBodyReader")

// readRawBody returns the first maxBodyBytes bytes of the request body as
// buffered by Coraza, independent of any body processor. The public
// types.Transaction interface owns RequestBodyReader; the plugintypes
// interface does not, hence the assertion. Reading here does not consume the
// buffer for the connector (every call gets its own reader).
func readRawBody(tx plugintypes.TransactionState) ([]byte, error) {
	src, ok := tx.(corazatypes.Transaction)
	if !ok {
		return nil, errNoBodyReader
	}
	r, err := src.RequestBodyReader()
	if err != nil {
		return nil, fmt.Errorf("RequestBodyReader: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// thresholdFromTX reads the optional TX:argus_threshold override. ok=false
// with valid=true means "not set": the sidecar verdict is used as-is.
// valid=false means "set but unusable": the caller must fail open.
func thresholdFromTX(txVars collection.Map) (threshold float64, set bool, valid bool) {
	values := txVars.Get(txThreshold)
	if len(values) == 0 {
		return 0, false, true
	}
	raw := firstValue(values)
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
		return 0, true, false
	}
	return f, true, true
}

var _ plugintypes.Action = (*mlcheckFn)(nil)
