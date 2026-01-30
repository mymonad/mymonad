.PHONY: all build ingest agent cli test clean

GO := go
BINDIR := bin

all: build

build: ingest agent cli

ingest:
	$(GO) build -o $(BINDIR)/mymonad-ingest ./cmd/mymonad-ingest

agent:
	$(GO) build -o $(BINDIR)/mymonad-agent ./cmd/mymonad-agent

cli:
	$(GO) build -o $(BINDIR)/mymonad-cli ./cmd/mymonad-cli

test:
	$(GO) test -v -race -cover ./...

test-coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf $(BINDIR)
	rm -f coverage.out coverage.html
