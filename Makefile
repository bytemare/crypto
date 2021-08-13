PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: lint
lint:
	@echo "Linting ..."
	@gofumports -w -local github.com/bytemare/crypto .
	@golangci-lint run --config=./.github/.golangci.yml ./...

.PHONY: license
license:

	@echo "Checking License headers ..."
	@addlicense -check -v -f .github/licence-header.tmpl *

.PHONY: test
test:
	@echo "Running all tests ..."
	@go test -v ./...

.PHONY: cover
cover:
	@echo "Testing with coverage ..."
	@go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=./coverage.out ./...
