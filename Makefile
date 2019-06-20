all: check-license build generate test

GO111MODULE=on
export GO111MODULE

GITHUB_URL=github.com/brancz/kube-rbac-proxy
GOOS?=$(shell uname -s | tr A-Z a-z)
GOARCH?=$(shell go env GOARCH)
OUT_DIR=_output
BIN?=kube-rbac-proxy
VERSION?=$(shell cat VERSION)
PKGS=$(shell go list ./... | grep -v /vendor/)
DOCKER_REPO?=quay.io/brancz/kube-rbac-proxy

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
	@CGO_ENABLED=0 go build --installsuffix cgo -o $(OUTPUT) $(GITHUB_URL)

container:
	docker build -t $(DOCKER_REPO):$(VERSION) .

curl-container:
	docker build -f ./examples/example-client/Dockerfile -t quay.io/brancz/krp-curl:v0.0.1 .

run-curl-container:
	@echo 'Example: curl -v -s -k -H "Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`" https://kube-rbac-proxy.default.svc:8443/metrics'
	kubectl run -i -t krp-curl --image=quay.io/brancz/krp-curl:v0.0.1 --restart=Never --command -- /bin/sh

grpcc-container:
	docker build -f ./examples/grpcc/Dockerfile -t mumoshu/grpcc:v0.0.1 .

test:
	@echo ">> running all tests"
	# install test dependencies
	@go test -i $(PKGS)
	# run the tests
	@go test  $(PKGS)

test-e2e:
	go test -timeout 55m -v ./test/e2e/ $(TEST_RUN_ARGS) --kubeconfig=$(KUBECONFIG)

generate: embedmd
	@echo ">> generating examples"
	@./scripts/generate-examples.sh
	@echo ">> generating docs"
	@./scripts/generate-help-txt.sh
	@$(GOPATH)/bin/embedmd -w `find ./ -path ./vendor -prune -o -name "*.md" -print`

embedmd:
	@go get github.com/campoy/embedmd

.PHONY: all check-license crossbuild build container curl-container test generate embedmd
