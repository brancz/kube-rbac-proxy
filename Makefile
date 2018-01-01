all: check-license build generate test

GITHUB_URL=github.com/brancz/kube-rbac-proxy
GOOS?=$(shell uname -s | tr A-Z a-z)
GOARCH?=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m)))
OUT_DIR=_output
BIN?=kube-rbac-proxy
VERSION?=$(shell cat VERSION)
PKGS=$(shell go list ./... | grep -v /vendor/)
DOCKER_REPO=quay.io/brancz/kube-rbac-proxy

check-license:
	@echo ">> checking license headers"
	@./scripts/check_license.sh

crossbuild:
	@GOOS=darwin ARCH=amd64 $(MAKE) -s build
	@GOOS=linux ARCH=amd64 $(MAKE) -s build
	@GOOS=windows ARCH=amd64 $(MAKE) -s build

build:
	@$(eval OUTPUT=$(OUT_DIR)/$(GOOS)/$(GOARCH)/$(BIN))
	@echo ">> building for $(GOOS)/$(GOARCH) to $(OUTPUT)"
	@mkdir -p $(OUT_DIR)/$(GOOS)/$(GOARCH)
	@CGO_ENABLED=0 go build -i --installsuffix cgo -o $(OUTPUT) $(GITHUB_URL)

container: build
	docker build -t $(DOCKER_REPO):$(VERSION) .

curl-container:
	docker build -f ./examples/example-client/Dockerfile -t quay.io/brancz/krp-curl:v0.0.1 .

test:
	@echo ">> running all tests"
	@go test -i $(PKGS)

generate: embedmd
	@echo ">> generating docs"
	@./scripts/generate-help-txt.sh
	@$(GOPATH)/bin/embedmd -w `find ./ -name "*.md"`

embedmd:
	@go get github.com/campoy/embedmd

.PHONY: all check-license build crossbuild compile test
