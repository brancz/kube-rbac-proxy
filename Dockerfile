FROM golang:1.10-alpine AS build
WORKDIR /go/src/github.com/brancz/kube-rbac-proxy
COPY . .
RUN go build .

FROM alpine:3.7
COPY --from=build /go/src/github.com/brancz/kube-rbac-proxy/kube-rbac-proxy .
ENTRYPOINT ["./kube-rbac-proxy"]
EXPOSE 8080
