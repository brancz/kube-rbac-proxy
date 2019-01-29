FROM registry.svc.ci.openshift.org/openshift/release:golang-1.10 AS builder
WORKDIR /go/src/github.com/brancz/kube-rbac-proxy
COPY . .
RUN make build && \
    cp _output/linux/$(go env GOARCH)/kube-rbac-proxy _output/kube-rbac-proxy

FROM  registry.svc.ci.openshift.org/openshift/origin-v4.0:base
LABEL io.k8s.display-name="kube-rbac-proxy" \
      io.k8s.description="This is a proxy, that can perform Kubernetes RBAC authorization." \
      io.openshift.tags="kubernetes" \
      maintainer="Frederic Branczyk <fbranczy@redhat.com>"

ARG FROM_DIRECTORY=/go/src/github.com/brancz/kube-rbac-proxy
COPY --from=builder ${FROM_DIRECTORY}/_output/kube-rbac-proxy  /usr/bin/kube-rbac-proxy

USER nobody
EXPOSE 8080
ENTRYPOINT ["/usr/bin/kube-rbac-proxy"]
