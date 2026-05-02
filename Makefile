.PHONY: build
build:
	go build -trimpath -ldflags="-s -w" ./...

.PHONY: test
test:
	go test -race ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...
	go tool editorconfig-checker

.PHONY: tidy
tidy:
	go mod tidy
