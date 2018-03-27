FROM golang:1.10-alpine AS build
RUN apk add --update make
WORKDIR /go/src/github.com/brancz/kube-rbac-proxy
COPY . .
RUN make build

FROM alpine:3.7
COPY --from=build /go/src/github.com/brancz/kube-rbac-proxy/_output/linux/amd64/kube-rbac-proxy .
ENTRYPOINT ["./kube-rbac-proxy"]
EXPOSE 8080
