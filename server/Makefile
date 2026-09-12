.PHONY: test relay sim

test:
	go test ./...

relay:
	go run ./cmd/relay -addr 127.0.0.1:43147 -data data/relay.json -web web

sim:
	go run ./cmd/sim -relay http://127.0.0.1:43147
