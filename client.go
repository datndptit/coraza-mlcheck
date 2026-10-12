// Copyright 2026 MobiFone ANM / Argus Sentinel integration
// SPDX-License-Identifier: Apache-2.0

package mlcheck

import (
	"fmt"
	"sync"
	"time"

	argusv1 "github.com/datndptit/coraza-mlcheck/proto/argusv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// clients caches gRPC clients keyed by socket path. grpc.ClientConn is
// concurrency-safe and meant to be long-lived; the underlying HTTP/2 stream
// multiplexes all requests, so one connection per socket is correct.
// Connections are established lazily (grpc.NewClient does not dial), so a
// missing sidecar never blocks config load; the first RPC fails fast and the
// action fails open.
var (
	clientsMu sync.RWMutex
	clients   = map[string]argusv1.ArgusSentinelClient{}
)

func getClient(socketPath string) (argusv1.ArgusSentinelClient, error) {
	clientsMu.RLock()
	if c, ok := clients[socketPath]; ok {
		clientsMu.RUnlock()
		return c, nil
	}
	clientsMu.RUnlock()

	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[socketPath]; ok {
		return c, nil
	}

	// "unix:<path>" targets the unix resolver's opaque/path forms: an
	// absolute POSIX path ("/run/argus/argus.sock") lands in URL.Path, a
	// Windows drive path ("C:/..." in local test builds) in URL.Opaque.
	// Both resolve to the same dial address; the "unix://" authority form
	// rejects non-empty hosts and thus cannot carry drive letters.
	target := "unix:" + socketPath
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1<<20), // 1 MiB ceiling for response
			grpc.MaxCallSendMsgSize(8<<20), // 8 MiB ceiling for request (body + headers)
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc.NewClient(%q): %w", target, err)
	}

	c := argusv1.NewArgusSentinelClient(conn)
	clients[socketPath] = c
	return c, nil
}
