FROM gcr.io/distroless/static:nonroot

USER 65532:65532

ARG BINARY=kube-rbac-proxy-linux-amd64
COPY _output/$BINARY /usr/local/bin/kube-rbac-proxy

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]
