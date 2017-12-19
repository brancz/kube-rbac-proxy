# kube-rbac-proxy

[![Docker Repository on Quay](https://quay.io/repository/brancz/kube-rbac-proxy/status "Docker Repository on Quay")](https://quay.io/repository/brancz/kube-rbac-proxy)

> NOTE: This project is *alpha* stage. Flags, configuration, behavior and design may change significantly in following releases.

The kube-rbac-proxy is a small HTTP proxy for a single upstream, that can perform RBAC authorization against the Kubernetes API using SubjectAccessReviews.

In Kubernetes clusters without NetworkPolicies any Pod can perform requests to every other Pod in the cluster. This proxy was developed in order to restrict requests to only those Pods, that present a valid and RBAC authorized token or client TLS certificate.

## Usage

The kube-rbac-proxy has all [`glog`](https://github.com/golang/glog) flags for logging purposes. To use the kube-rbac-proxy there are a few flags you may want to set:

* `--upstream`: This is the upstream you want to proxy to.
* `--resource-attributes-file`: This file specifies details on the SubjectAccessReview you want to be performed on a request. For example, this could contain that an entity performing a request has to be allowed to perform a `get` on the Deployment called `my-frontend-app`.

See the `examples/` directory for the following examples:

* [non-resource-url example](examples/non-resource-url)
* [resource-attributes example](examples/resource-attributes)

All command line flags:

[embedmd]:# (_output/help.txt)
```txt
$ kube-rbac-proxy -h
Usage of _output/linux/amd64/kube-rbac-proxy:
      --alsologtostderr                   log to standard error as well as files
      --client-ca-file string             If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.
      --listen-address string             The address the kube-rbac-proxy HTTP server should listen on. (default ":8080")
      --log_backtrace_at traceLocation    when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                    If non-empty, write log files in this directory
      --logtostderr                       log to standard error instead of files
      --resource-attributes-file string   File spec of attributes-record to use for SubjectAccessReview. If unspecified, requests will attempted to be verified through non-resource-url attributes in the SubjectAccessReview.
      --stderrthreshold severity          logs at or above this threshold go to stderr (default 2)
      --upstream string                   The upstream URL to proxy to once requests have successfully been authenticated and authorized.
  -v, --v Level                           log level for V logs
      --vmodule moduleSpec                comma-separated list of pattern=N settings for file-filtered logging
```

## Why?

You may ask yourself, why not just use the Kubernetes apiserver proxy functionality? There are two reasons why this makes sense, the first is to take load off of the Kubernetes API, so it can be used for actual requests serving the cluster components, rather than in order to serve client requests. The second and more important reason is, this proxy is intended to be a sidecar that accepts incoming HTTP requests. This way, one can ensure that a request is truly authorized, instead of being able to access an application simply because an entity has network access to it.

## Motivation

I developed this proxy in order to be able to protect [Prometheus](https://prometheus.io/) metrics endpoints. In a scenario, where an attacker might obtain full control over a Pod, that attacker would have the ability to discover a lot of information about the workload as well as the current load of the respective workload. This information could originate for example from the [node-exporter](https://github.com/prometheus/node_exporter) and [kube-stat-metrics](https://github.com/kubernetes/kube-state-metrics). Both of those metric sources can commonly be found in Prometheus monitoring stacks on [Kubernetes](https://kubernetes.io/).

This project was created to specifically solve the above problem, however, I felt there is a larger need for such a proxy in general.

## How does it work?

On an incoming request, kube-rbac-proxy first figures out which user is performing the request. The kube-rbac-proxy supports using client TLS certificates, as well as tokens. In case of a client certificates, the certificate is simply validated against the configured CA. In case of a bearer token being presented, the `authentication.k8s.io` is used to perform a `TokenReview`.

Once a user has been authenticated, again the `authentication.k8s.io` is used to perform a `SubjectAccessReview`, in order to authorize the respective request, to ensure the authenticated user has the required RBAC roles.

## Differentiation to [Envoy](https://www.envoyproxy.io/)/[Istio](https://istio.io/)

This projects is not intended to compete with Envoy or IstioMesh. Although on the surface they seem similar, the goals and usage complement each other. It's perfectly ok to use Envoy as the ingress point of traffic of a Pod, which then forwards traffic to the kube-rbac-proxy, which in turn then proxies to the actually serving application.

Additionally, to my knowledge Envoy neither has nor plans Kubernetes specific RBAC/AuthZ support (maybe it shouldn’t even). My knowledge may very well be incomplete, please point out if it is. After all I'm happy if I don't have to maintain more code, but as long as this serves a purpose to me and no other project can provide it, I'll maintain this.

## Roadmap

PR are more than welcome!

* Tests
* TLS support
* OIDC support
