FROM gcr.io/distroless/static:nonroot

ARG BINARY=kube-rbac-proxy-linux-amd64
COPY _output/$BINARY /usr/local/bin/kube-rbac-proxy
EXPOSE 8080
USER 1001:1001

ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]
