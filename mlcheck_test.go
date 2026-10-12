// Copyright 2026 MobiFone ANM / Argus Sentinel integration
// SPDX-License-Identifier: Apache-2.0

package mlcheck

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	argusv1 "github.com/datndptit/coraza-mlcheck/proto/argusv1"
	"google.golang.org/grpc"
)

// ---------------------------------------------------------------------------
// mock sidecar
// ---------------------------------------------------------------------------

type mockSentinel struct {
	mu       sync.Mutex
	requests []*argusv1.ClassifyRequest
	score    float64
	clean    bool
	rpcErr   error
	delay    time.Duration
}

func (m *mockSentinel) Classify(ctx context.Context, req *argusv1.ClassifyRequest) (*argusv1.ClassifyResponse, error) {
	m.mu.Lock()
	m.requests = append(m.requests, req)
	score, clean, rpcErr, delay := m.score, m.clean, m.rpcErr, m.delay
	m.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if rpcErr != nil {
		return nil, rpcErr
	}
	resp := &argusv1.ClassifyResponse{IsClean: clean, RiskScore: score}
	if !clean {
		resp.Detections = map[string]float64{"attack": score}
	}
	return resp, nil
}

func (m *mockSentinel) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

func (m *mockSentinel) last(t *testing.T) *argusv1.ClassifyRequest {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		t.Fatal("sidecar received no request")
	}
	return m.requests[len(m.requests)-1]
}

// startMock runs the mock over a real Unix domain socket and returns its
// path. The suite skips (rather than fails) on hosts without unix sockets.
func startMock(t *testing.T, m *mockSentinel) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "argus.sock")
	if runtime.GOOS == "windows" {
		sock = filepath.ToSlash(sock)
	}
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable on this host: %v", err)
	}
	srv := grpc.NewServer()
	argusv1.RegisterArgusSentinelServer(srv, m)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return sock
}

// resetRuntimeForTest clears the package-level caches (config, clients,
// limiter/breaker state, counters) so tests observe only their own traffic.
func resetRuntimeForTest(t *testing.T, sock string) {
	t.Helper()
	if sock != "" {
		t.Setenv("ARGUS_SOCKET", sock)
	}
	resetConfigForTests()
	statesMu.Lock()
	states = map[string]*socketState{}
	statesMu.Unlock()
	clientsMu.Lock()
	clients = map[string]argusv1.ArgusSentinelClient{}
	clientsMu.Unlock()
	stats.calls.Store(0)
	stats.dup.Store(0)
	stats.rpcAttempts.Store(0)
	stats.ok.Store(0)
	for i := range stats.failures {
		stats.failures[i].Store(0)
	}
	for i := range stats.latency {
		stats.latency[i].Store(0)
	}
	stats.lastFlush.Store(0)
}

// ---------------------------------------------------------------------------
// WAF helpers
// ---------------------------------------------------------------------------

const baseDirectives = `SecRequestBodyAccess On
SecRuleEngine On
SecRequestBodyLimit 1048576
`

const mlcheckPass = `SecRule REQUEST_URI "@unconditionalMatch" "id:100,phase:2,pass,nolog,noauditlog,mlcheck"`
const detectRule = `SecRule TX:argus_is_clean "@streq 0" "id:101,phase:2,deny,status:403,log,noauditlog,msg:'Argus v4 detected'"`
const errorRule = `SecRule TX:argus_error "@rx .+" "id:102,phase:2,pass,log,noauditlog,msg:'Argus unavailable: %{tx.argus_error}'"`

func newWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("coraza.NewWAF: %v", err)
	}
	return waf
}

type testRequest struct {
	method      string
	uri         string
	headers     [][2]string
	contentType string
	body        string
}

type txResult struct {
	tx   map[string]string
	deny *corazatypes.Interruption
}

func runRequest(t *testing.T, waf coraza.WAF, r testRequest) txResult {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection("127.0.0.1", 4242, "127.0.0.1", 8080)
	tx.ProcessURI(r.uri, r.method, "HTTP/1.1")
	if r.contentType != "" {
		tx.AddRequestHeader("Content-Type", r.contentType)
	}
	for _, h := range r.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Fatalf("unexpected interruption after request headers: %+v", it)
	}
	if r.body != "" {
		it, _, err := tx.ReadRequestBodyFrom(strings.NewReader(r.body))
		if err != nil {
			t.Fatalf("ReadRequestBodyFrom: %v", err)
		}
		if it != nil {
			t.Fatalf("unexpected interruption while buffering the body: %+v", it)
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatalf("ProcessRequestBody: %v", err)
	}

	reader, err := tx.RequestBodyReader()
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := io.ReadAll(reader)
	if err != nil || string(forwarded) != r.body {
		t.Fatalf("action altered upstream body: err=%v bytes=%d expected=%d", err, len(forwarded), len(r.body))
	}
	state, ok := tx.(plugintypes.TransactionState)
	if !ok {
		t.Fatalf("transaction %T does not implement plugintypes.TransactionState", tx)
	}
	txv := state.Variables().TX()
	res := txResult{tx: map[string]string{}, deny: it}
	for _, name := range []string{txIsClean, txRiskScore, txDetections, txStatus, txError, txSkip, txThreshold} {
		res.tx[name] = firstValue(txv.Get(name))
	}
	return res
}

// ---------------------------------------------------------------------------
// integration tests
// ---------------------------------------------------------------------------

// TestBodyMatrix is the regression test for the pre-v4 bug: REQUEST_BODY is
// empty for JSON/XML bodies even though the buffer holds the raw bytes. The
// action must forward the raw body prefix for every body kind.
func TestBodyMatrix(t *testing.T) {
	mock := &mockSentinel{score: 0.01, clean: true}
	sock := startMock(t, mock)
	resetRuntimeForTest(t, sock)

	cases := []struct {
		name        string
		contentType string
		body        string
	}{
		{"urlencoded", "application/x-www-form-urlencoded", "user=admin&pass=secret"},
		{"json", "application/json", `{"text":"<script>alert(document.cookie)</script>"}`},
		{"xml", "application/xml", `<note><body>&lt;script&gt;</body></note>`},
		{"raw", "application/octet-stream", "\x00\x01binary-payload\xff"},
	}
	waf := newWAF(t, baseDirectives+mlcheckPass+"\n")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := mock.count()
			res := runRequest(t, waf, testRequest{
				method: "POST", uri: "/comment", contentType: tc.contentType, body: tc.body,
			})
			if res.tx[txStatus] != statusOK {
				t.Fatalf("status = %q (error=%q), want ok", res.tx[txStatus], res.tx[txError])
			}
			if got := mock.count(); got != before+1 {
				t.Fatalf("sidecar calls = %d, want %d", got, before+1)
			}
			if got := string(mock.last(t).GetBody()); got != tc.body {
				t.Fatalf("sidecar body = %q, want raw %q", got, tc.body)
			}
		})
	}
}

// TestDetectRuleIntegration runs the full pipeline: mlcheck writes the
// verdict, a downstream rule denies flagged requests and stays inert for
// clean ones.
func TestDetectRuleIntegration(t *testing.T) {
	mock := &mockSentinel{score: 0.999, clean: false}
	sock := startMock(t, mock)
	resetRuntimeForTest(t, sock)

	waf := newWAF(t, baseDirectives+mlcheckPass+"\n"+detectRule+"\n")

	res := runRequest(t, waf, testRequest{method: "GET", uri: "/products?id=1+or+1=1"})
	if res.deny == nil || res.deny.Status != 403 {
		t.Fatalf("attack verdict did not deny: %+v", res.deny)
	}
	if res.tx[txIsClean] != "0" || res.tx[txDetections] != "attack" {
		t.Fatalf("verdict TX = is_clean=%q detections=%q, want 0/attack", res.tx[txIsClean], res.tx[txDetections])
	}
	if res.tx[txRiskScore] != "0.999" {
		t.Fatalf("risk score = %q, want 0.999 (full precision)", res.tx[txRiskScore])
	}

	mock.mu.Lock()
	mock.clean, mock.score = true, 0.00012
	mock.mu.Unlock()
	res = runRequest(t, waf, testRequest{method: "GET", uri: "/products?id=42"})
	if res.deny != nil {
		t.Fatalf("clean verdict denied: %+v", res.deny)
	}
	if res.tx[txIsClean] != "1" || res.tx[txDetections] != "" {
		t.Fatalf("clean TX = is_clean=%q detections=%q, want 1/", res.tx[txIsClean], res.tx[txDetections])
	}
}

// TestFailOpenWhenSidecarDown: no listener on the socket. Traffic must flow
// (no interruption from the verdict rules), the failure must be recorded, and
// no clean verdict may be written.
func TestFailOpenWhenSidecarDown(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "missing.sock") // never created
	if runtime.GOOS == "windows" {
		sock = filepath.ToSlash(sock)
	}
	resetRuntimeForTest(t, sock)

	waf := newWAF(t, baseDirectives+mlcheckPass+"\n"+detectRule+"\n"+errorRule+"\n")
	res := runRequest(t, waf, testRequest{method: "GET", uri: "/anything"})

	if res.deny != nil {
		t.Fatalf("sidecar down must fail open, got interruption: %+v", res.deny)
	}
	if res.tx[txStatus] != statusError {
		t.Fatalf("status = %q, want error", res.tx[txStatus])
	}
	switch res.tx[txError] {
	case "client_init", "rpc_error", "rpc_timeout":
	default:
		t.Fatalf("error = %q, want a connection failure reason", res.tx[txError])
	}
	if res.tx[txIsClean] != "" {
		t.Fatalf("is_clean = %q, want empty (no verdict on failure)", res.tx[txIsClean])
	}
	if res.tx[txRiskScore] != "" {
		t.Fatalf("risk score = %q, want empty on failure", res.tx[txRiskScore])
	}
	snap := SnapshotStats()
	if snap.OK != 0 {
		t.Fatalf("OK counter = %d, failures must not count as clean verdicts", snap.OK)
	}
	if snap.Failures["rpc_error"]+snap.Failures["rpc_timeout"]+snap.Failures["client_init"] != 1 {
		t.Fatalf("failure counters = %+v, want exactly one connection failure", snap.Failures)
	}
}

// TestThresholdFromTXOverridesSidecar: TX:argus_threshold re-decides the
// verdict from the raw probability, keeping is_clean/detections consistent
// with the effective threshold even when the sidecar disagrees.
func TestThresholdFromTXOverridesSidecar(t *testing.T) {
	mock := &mockSentinel{score: 0.95, clean: true} // sidecar threshold would say clean
	sock := startMock(t, mock)
	resetRuntimeForTest(t, sock)

	setThreshold := `SecAction "id:99,phase:2,pass,nolog,noauditlog,setvar:'tx.argus_threshold=0.9'"`
	waf := newWAF(t, baseDirectives+setThreshold+"\n"+mlcheckPass+"\n")

	res := runRequest(t, waf, testRequest{method: "GET", uri: "/x"})
	if res.tx[txIsClean] != "0" || res.tx[txDetections] != "attack" {
		t.Fatalf("0.95 > 0.9 must flag: is_clean=%q detections=%q", res.tx[txIsClean], res.tx[txDetections])
	}

	// Sidecar says attack, but the rule threshold is not crossed: the
	// override wins and no attack label may remain.
	mock.mu.Lock()
	mock.clean, mock.score = false, 0.5
	mock.mu.Unlock()
	res = runRequest(t, waf, testRequest{method: "GET", uri: "/y"})
	if res.tx[txIsClean] != "1" || res.tx[txDetections] != "" {
		t.Fatalf("0.5 !> 0.9 must stay clean: is_clean=%q detections=%q", res.tx[txIsClean], res.tx[txDetections])
	}
}

// TestInvalidThresholdFailsOpen: a bad TX threshold must fail open with an
// error and must NOT silently fall back to another threshold (no RPC).
func TestInvalidThresholdFailsOpen(t *testing.T) {
	mock := &mockSentinel{score: 0.99, clean: false}
	sock := startMock(t, mock)
	resetRuntimeForTest(t, sock)

	setThreshold := `SecAction "id:99,phase:2,pass,nolog,noauditlog,setvar:'tx.argus_threshold=not-a-number'"`
	waf := newWAF(t, baseDirectives+setThreshold+"\n"+mlcheckPass+"\n")

	res := runRequest(t, waf, testRequest{method: "GET", uri: "/x"})
	if res.tx[txStatus] != statusError || res.tx[txError] != "invalid_threshold" {
		t.Fatalf("status/error = %q/%q, want error/invalid_threshold", res.tx[txStatus], res.tx[txError])
	}
	if res.tx[txIsClean] != "" {
		t.Fatalf("is_clean = %q, want empty", res.tx[txIsClean])
	}
	if mock.count() != 0 {
		t.Fatalf("sidecar calls = %d, want 0 (no fallback threshold)", mock.count())
	}
}

// TestDuplicateInvocationSingleRPC: two mlcheck rules in one transaction must
// produce exactly one RPC and keep the first verdict.
func TestDuplicateInvocationSingleRPC(t *testing.T) {
	mock := &mockSentinel{score: 0.9, clean: false}
	sock := startMock(t, mock)
	resetRuntimeForTest(t, sock)

	rule1 := `SecRule REQUEST_URI "@unconditionalMatch" "id:100,phase:2,pass,nolog,noauditlog,mlcheck"`
	rule2 := `SecRule REQUEST_URI "@unconditionalMatch" "id:101,phase:2,pass,nolog,noauditlog,mlcheck"`
	waf := newWAF(t, baseDirectives+rule1+"\n"+rule2+"\n")

	res := runRequest(t, waf, testRequest{method: "GET", uri: "/x"})
	if got := mock.count(); got != 1 {
		t.Fatalf("sidecar calls = %d, want exactly 1", got)
	}
	if res.tx[txStatus] != statusOK || res.tx[txIsClean] != "0" {
		t.Fatalf("first verdict clobbered: status=%q is_clean=%q", res.tx[txStatus], res.tx[txIsClean])
	}
	if res.tx[txSkip] != skipDuplicate {
		t.Fatalf("argus_skip = %q, want %q", res.tx[txSkip], skipDuplicate)
	}
	snap := SnapshotStats()
	if snap.Calls != 2 || snap.Duplicates != 1 || snap.RPCAttempts != 1 || snap.OK != 1 {
		t.Fatalf("counters = calls:%d dup:%d rpc:%d ok:%d, want 2/1/1/1",
			snap.Calls, snap.Duplicates, snap.RPCAttempts, snap.OK)
	}
}

// TestHeadersJoinAndURIRaw: duplicate headers are joined "; " in order, only
// user-agent/referer/cookie are sent, and REQUEST_URI_RAW is preferred.
func TestHeadersJoinAndURIRaw(t *testing.T) {
	mock := &mockSentinel{score: 0.01, clean: true}
	sock := startMock(t, mock)
	resetRuntimeForTest(t, sock)

	waf := newWAF(t, baseDirectives+mlcheckPass+"\n")
	runRequest(t, waf, testRequest{
		method: "GET",
		uri:    "http://example.com/a/b?x=1",
		headers: [][2]string{
			{"User-Agent", "curl/8"},
			{"user-agent", "scanner/1"},
			{"Referer", "https://ref.example/"},
			{"Cookie", "a=1"},
			{"Cookie", "b=2"},
			{"Authorization", "Bearer secret-token"},
		},
	})

	req := mock.last(t)
	if got := req.GetHeaders()["user-agent"]; got != "curl/8; scanner/1" {
		t.Fatalf("user-agent = %q, want duplicate values joined in order", got)
	}
	if got := req.GetHeaders()["cookie"]; got != "a=1; b=2" {
		t.Fatalf("cookie = %q, want duplicate values joined in order", got)
	}
	if got := req.GetHeaders()["referer"]; got != "https://ref.example/" {
		t.Fatalf("referer = %q", got)
	}
	for name := range req.GetHeaders() {
		switch name {
		case "user-agent", "referer", "cookie":
		default:
			t.Fatalf("unexpected header sent to the model: %q", name)
		}
	}
	if got := req.GetUri(); got != "http://example.com/a/b?x=1" {
		t.Fatalf("uri = %q, want the raw absolute-form request target", got)
	}
}

// TestWrongPhaseFailsOpen: mlcheck on a phase-1 rule has no buffered body and
// must report a configuration error instead of classifying emptiness.
func TestWrongPhaseFailsOpen(t *testing.T) {
	mock := &mockSentinel{score: 0.99, clean: false}
	sock := startMock(t, mock)
	resetRuntimeForTest(t, sock)

	phase1 := `SecRule REQUEST_URI "@unconditionalMatch" "id:100,phase:1,pass,nolog,noauditlog,mlcheck"`
	waf := newWAF(t, baseDirectives+phase1+"\n"+detectRule+"\n")

	res := runRequest(t, waf, testRequest{method: "GET", uri: "/x"})
	if res.tx[txStatus] != statusError || res.tx[txError] != "wrong_phase" {
		t.Fatalf("status/error = %q/%q, want error/wrong_phase", res.tx[txStatus], res.tx[txError])
	}
	if mock.count() != 0 {
		t.Fatalf("sidecar calls = %d, want 0 for a phase-1 invocation", mock.count())
	}
	if res.deny != nil {
		t.Fatalf("wrong phase must fail open, got interruption %+v", res.deny)
	}
}

// ---------------------------------------------------------------------------
// unit tests
// ---------------------------------------------------------------------------

func TestLimiter(t *testing.T) {
	l := newLimiter(2)
	deadline := time.Now().Add(time.Second)

	if !l.acquire(deadline, 0) || !l.acquire(deadline, 0) {
		t.Fatal("limiter refused within capacity")
	}
	if l.acquire(deadline, time.Millisecond) {
		t.Fatal("limiter admitted above capacity")
	}
	l.release()
	if !l.acquire(deadline, 0) {
		t.Fatal("limiter did not reuse a released slot")
	}
}

func TestBreaker(t *testing.T) {
	log := nopLogger{}
	b := newBreaker(2, 10*time.Millisecond)
	now := time.Now()
	first := b.acquire(now)
	stale := b.acquire(now)
	if first == nil || stale == nil {
		t.Fatal("closed breaker")
	}
	first.failure(now, log)
	second := b.acquire(now)
	if second == nil {
		t.Fatal("opened too early")
	}
	second.failure(now, log)
	if b.acquire(now) != nil {
		t.Fatal("open breaker admitted request")
	}
	stale.success(log)
	if b.acquire(now) != nil {
		t.Fatal("stale success reopened circuit")
	}
	later := now.Add(20 * time.Millisecond)
	probe := b.acquire(later)
	if probe == nil || b.acquire(later) != nil {
		t.Fatal("half-open must admit one probe")
	}
	probe.failure(later, log)
	probe.success(log)
	if b.acquire(later) != nil {
		t.Fatal("failed probe must reopen")
	}
	recovered := b.acquire(later.Add(20 * time.Millisecond))
	if recovered == nil {
		t.Fatal("missing recovery probe")
	}
	recovered.success(log)
	if b.acquire(later.Add(20*time.Millisecond)) == nil {
		t.Fatal("recovery failed")
	}
}

func TestThresholdParsing(t *testing.T) {
	waf := newWAF(t, baseDirectives+`SecAction "id:99,phase:2,pass,nolog,noauditlog,setvar:'tx.argus_threshold=0.5'"
`)
	tx := waf.NewTransaction()
	defer tx.Close()
	state := tx.(plugintypes.TransactionState)

	// Not set: valid=false, set=false.
	th, set, valid := thresholdFromTX(state.Variables().TX())
	if set || !valid || th != 0 {
		t.Fatalf("unset threshold: th=%v set=%v valid=%v", th, set, valid)
	}

	// Out of range: set but invalid.
	state.Variables().TX().Set(txThreshold, []string{"1.5"})
	if _, set, valid = thresholdFromTX(state.Variables().TX()); !set || valid {
		t.Fatal("1.5 must be rejected as out of range")
	}
	state.Variables().TX().Set(txThreshold, []string{"abc"})
	if _, set, valid = thresholdFromTX(state.Variables().TX()); !set || valid {
		t.Fatal("abc must be rejected")
	}
	state.Variables().TX().Set(txThreshold, []string{"0.998175"})
	if th, set, valid = thresholdFromTX(state.Variables().TX()); !set || !valid || th != 0.998175 {
		t.Fatalf("0.998175: th=%v set=%v valid=%v", th, set, valid)
	}
}

func TestInitArg(t *testing.T) {
	resetRuntimeForTest(t, "/run/argus/argus.sock")
	a := &mlcheckFn{}

	if err := a.Init(nil, "relative/path.sock"); err != errInvalidArg {
		t.Fatalf("relative path: err = %v, want errInvalidArg", err)
	}
	if err := a.Init(nil, ""); err != nil || a.socketPath != "/run/argus/argus.sock" {
		t.Fatalf("empty arg: err=%v socket=%q, want env default", err, a.socketPath)
	}
	if err := a.Init(nil, "/custom/argus.sock"); err != nil || a.socketPath != "/custom/argus.sock" {
		t.Fatalf("explicit path: err=%v socket=%q", err, a.socketPath)
	}
}

func TestSummaryAndCounters(t *testing.T) {
	resetRuntimeForTest(t, "/run/argus/argus.sock")
	t.Setenv("ARGUS_METRICS_INTERVAL_S", "1")
	resetConfigForTests()

	recordCall()
	recordCall()
	recordDuplicate()
	recordRPCAttempt()
	recordVerdict(300 * time.Microsecond)
	recordFailure(reasonOverload, 3*time.Millisecond)
	recordFailure(reasonRPCTimeout, 500*time.Millisecond) // overflow bucket

	snap := SnapshotStats()
	if snap.Calls != 2 || snap.Duplicates != 1 || snap.RPCAttempts != 1 || snap.OK != 1 {
		t.Fatalf("counters = %+v", snap)
	}
	if snap.Failures["overload"] != 1 || snap.Failures["rpc_timeout"] != 1 {
		t.Fatalf("failures = %+v", snap.Failures)
	}
	if snap.LatencyBuckets["<=0.5ms"] != 1 || snap.LatencyBuckets["<=5ms"] != 1 || snap.LatencyBuckets[">200ms"] != 1 {
		t.Fatalf("latency buckets = %+v", snap.LatencyBuckets)
	}
	if q := formatQuantiles(); !strings.Contains(q, "p50") || !strings.Contains(q, "n=3") {
		t.Fatalf("quantiles = %q", q)
	}

	// First flush arms the timer without logging; a flush after the interval
	// logs exactly one summary; one inside the interval stays silent.
	cap := &captureLogger{}
	flushSummary(cap)
	if len(cap.lines) != 0 {
		t.Fatalf("first flush logged: %v", cap.lines)
	}
	flushSummary(cap)
	if len(cap.lines) != 0 {
		t.Fatalf("flush within the interval logged: %v", cap.lines)
	}
	stats.lastFlush.Store(time.Now().Add(-2 * time.Second).UnixNano())
	flushSummary(cap)
	if len(cap.lines) != 1 {
		t.Fatalf("expected exactly one summary line, got %v", cap.lines)
	}
	line := cap.lines[0]
	for _, want := range []string{"calls=2", "ok=1", "skipped_duplicate=1", "rpc_attempts=1", "overload=1", "rpc_timeout=1"} {
		if !strings.Contains(line, want) {
			t.Fatalf("summary %q missing %q", line, want)
		}
	}
}

// captureLogger records one line per Info event (fields plus Msg).
type captureLogger struct{ lines []string }

func (c *captureLogger) WithOutput(w io.Writer) debuglog.Logger               { return c }
func (c *captureLogger) WithLevel(lvl debuglog.Level) debuglog.Logger         { return c }
func (c *captureLogger) With(fields ...debuglog.ContextField) debuglog.Logger { return c }
func (c *captureLogger) Trace() debuglog.Event                                { return nopEvent{} }
func (c *captureLogger) Debug() debuglog.Event                                { return nopEvent{} }
func (c *captureLogger) Info() debuglog.Event                                 { return &captureEvent{logger: c} }
func (c *captureLogger) Warn() debuglog.Event                                 { return nopEvent{} }
func (c *captureLogger) Error() debuglog.Event                                { return nopEvent{} }

type captureEvent struct {
	logger *captureLogger
	parts  []string
}

func (e *captureEvent) Msg(msg string) {
	e.parts = append(e.parts, msg)
	e.logger.lines = append(e.logger.lines, strings.Join(e.parts, " "))
}
func (e *captureEvent) Str(key, val string) debuglog.Event {
	e.parts = append(e.parts, key+"="+val)
	return e
}
func (e *captureEvent) Err(err error) debuglog.Event {
	if err != nil {
		e.parts = append(e.parts, "err="+err.Error())
	}
	return e
}
func (e *captureEvent) Bool(key string, b bool) debuglog.Event {
	e.parts = append(e.parts, fmt.Sprintf("%s=%v", key, b))
	return e
}
func (e *captureEvent) Int(key string, i int) debuglog.Event {
	e.parts = append(e.parts, fmt.Sprintf("%s=%d", key, i))
	return e
}
func (e *captureEvent) Uint(key string, i uint) debuglog.Event {
	e.parts = append(e.parts, fmt.Sprintf("%s=%d", key, i))
	return e
}
func (e *captureEvent) Stringer(key string, val fmt.Stringer) debuglog.Event {
	e.parts = append(e.parts, key+"="+val.String())
	return e
}
func (e *captureEvent) IsEnabled() bool { return true }

// nopLogger is a minimal debuglog.Logger for unit tests.
type nopLogger struct{}

func (nopLogger) WithOutput(w io.Writer) debuglog.Logger               { return nopLogger{} }
func (nopLogger) WithLevel(lvl debuglog.Level) debuglog.Logger         { return nopLogger{} }
func (nopLogger) With(fields ...debuglog.ContextField) debuglog.Logger { return nopLogger{} }
func (nopLogger) Trace() debuglog.Event                                { return nopEvent{} }
func (nopLogger) Debug() debuglog.Event                                { return nopEvent{} }
func (nopLogger) Info() debuglog.Event                                 { return nopEvent{} }
func (nopLogger) Warn() debuglog.Event                                 { return nopEvent{} }
func (nopLogger) Error() debuglog.Event                                { return nopEvent{} }

type nopEvent struct{}

func (nopEvent) Msg(msg string)                                       {}
func (nopEvent) Str(key, val string) debuglog.Event                   { return nopEvent{} }
func (nopEvent) Err(err error) debuglog.Event                         { return nopEvent{} }
func (nopEvent) Bool(key string, b bool) debuglog.Event               { return nopEvent{} }
func (nopEvent) Int(key string, i int) debuglog.Event                 { return nopEvent{} }
func (nopEvent) Uint(key string, i uint) debuglog.Event               { return nopEvent{} }
func (nopEvent) Stringer(key string, val fmt.Stringer) debuglog.Event { return nopEvent{} }
func (nopEvent) IsEnabled() bool                                      { return false }

func TestEmptyThresholdIsInvalid(t *testing.T) {
	waf := newWAF(t, baseDirectives)
	tx := waf.NewTransaction()
	defer tx.Close()
	vars := tx.(plugintypes.TransactionState).Variables().TX()
	vars.Set(txThreshold, []string{""})
	if _, set, valid := thresholdFromTX(vars); !set || valid {
		t.Fatal("explicit empty threshold must be invalid")
	}
}

func TestQueueWaitZero(t *testing.T) {
	t.Setenv("ARGUS_QUEUE_WAIT_MS", "0")
	if loadConfig().queueWait != 0 {
		t.Fatal("zero must disable queue waiting")
	}
}

func TestInvalidResponseFailsOpen(t *testing.T) {
	for _, p := range []float64{math.NaN(), math.Inf(1), -0.1, 1.1} {
		t.Run(fmt.Sprint(p), func(t *testing.T) {
			mock := &mockSentinel{score: p, clean: false}
			resetRuntimeForTest(t, startMock(t, mock))
			waf := newWAF(t, baseDirectives+mlcheckPass+"\n"+detectRule)
			r := runRequest(t, waf, testRequest{method: "GET", uri: "/"})
			if r.deny != nil || r.tx[txStatus] != statusError || r.tx[txError] != "invalid_response" || r.tx[txRiskScore] != "" {
				t.Fatalf("invalid score was accepted: %+v", r)
			}
		})
	}
}

func TestRPCDeadlineFailsOpen(t *testing.T) {
	mock := &mockSentinel{score: 1, clean: false, delay: 250 * time.Millisecond}
	resetRuntimeForTest(t, startMock(t, mock))
	t.Setenv("ARGUS_TIMEOUT_MS", "20")
	waf := newWAF(t, baseDirectives+mlcheckPass+"\n"+detectRule)
	r := runRequest(t, waf, testRequest{method: "GET", uri: "/"})
	if r.deny != nil || r.tx[txError] != "rpc_timeout" {
		t.Fatalf("timeout failed: %+v", r)
	}
}
