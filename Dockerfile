FROM alpine:3.7

COPY _output/linux/amd64/kube-rbac-proxy /

ENTRYPOINT ["/kube-rbac-proxy"]

EXPOSE 8080
