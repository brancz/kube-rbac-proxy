FROM gcr.io/distroless/static

COPY _output/linux/$(go env GOARCH)/kube-rbac-proxy /usr/local/bin/kube-rbac-proxy

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]
