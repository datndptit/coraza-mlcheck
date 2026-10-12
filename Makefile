# Codegen and development helpers for the mlcheck Coraza action.
# The module is normally built into Caddy by docker/caddy/Dockerfile via
# xcaddy; these targets are for local development and testing.
#
# Requirements (pick one):
#   - buf (preferred): https://buf.build/docs/installation
#   - protoc + protoc-gen-go + protoc-gen-go-grpc
#
# With buf, install the local plugins once:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

.PHONY: proto proto-protoc proto-remote tidy build test vet clean

# Default: buf with local plugins (no remote plugin calls, no protoc needed).
proto: proto-local
proto-local:
	buf generate --template buf.gen.local.yaml

# Historical entries kept for parity with the pre-v4 bundle.
proto-buf:
	buf generate

proto-protoc:
	protoc \
	  --go_out=. --go_opt=paths=source_relative \
	  --go-grpc_out=. --go-grpc_opt=paths=source_relative,require_unimplemented_servers=false \
	  proto/argusv1/argus.proto

tidy:
	go mod tidy

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f proto/argusv1/*.pb.go
