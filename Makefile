.PHONY: fmt test vet build run clean

fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -o bin/agentguard ./cmd/agentguard

run:
	go run ./cmd/agentguard run

clean:
	rm -rf bin .agentguard
