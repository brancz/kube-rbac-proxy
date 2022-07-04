ARG GOARCH=amd64
ARG GOOS=linux
FROM golang:1.18-alpine as builder

WORKDIR /go/src/kube-rbac-proxy

COPY . .
RUN apk update && apk add --no-cache make && make build

FROM gcr.io/distroless/static:nonroot-$GOARCH

ARG GOARCH=amd64
ARG GOOS=linux
COPY --from=builder /go/src/kube-rbac-proxy/_output/kube-rbac-proxy /usr/local/bin/kube-rbac-proxy
EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]
