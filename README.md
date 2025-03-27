# kube-rbac-proxy

[![Docker Repository on Quay](https://quay.io/repository/brancz/kube-rbac-proxy/status "Docker Repository on Quay")](https://quay.io/repository/brancz/kube-rbac-proxy)

> NOTE: This project is *alpha* stage. Flags, configuration, behavior and design may change significantly in following releases.

The kube-rbac-proxy is a small HTTP proxy for a single upstream, that can perform RBAC authorization against the Kubernetes API using [SubjectAccessReview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/).

In Kubernetes clusters without NetworkPolicies any Pod can perform requests to every other Pod in the cluster. This proxy was developed in order to restrict requests to only those Pods, that present a valid and RBAC authorized token or client TLS certificate.

## Usage

### Migration guide from previous kube-rbac-proxy versions

To get kube-rbac-proxy accepted as an official Kubernetes SIG Auth repository, we had to rewrite much of the original code. While this was hugely benefitial to the project itself, it brought breaking changes in terms of availability of some options. The changes in options were as follows:

#### No longer available:
- `--insecure-listen-addres` - the proxy is handling authentication information and will no longer run in an unsafe mode
- `--auth-header-fields-enabled` - its value is derived from at least one of `--auth-header-groups-field-name` or `--auth-header-user-field-name` being set
- `--tls-reload-interval` - upstream Kubernetes TLS material is now being reloaded by Kubernetes upstream code which chooses its own reasonable defaults
- **infix regex** for `--allow-paths` and `--ignore-paths` - the proxy now uses postfix matching with `*` as its sole wildcard operator, instead of infix matching with different wildcard operators:
  - `/api/v1/*` matches now `/api/v1`, `/api/v1/foo` and `/api/v1/foo/bar`, **previously** it didn't match `/api/v1/foo/bar`.
  - `/api/v1/*/values` creates an error on server startup, **previously** it matched `/api/v1/foo/values` and `/api/v1/bar/values`.
  - details: [Allow Path and Ignore Path changes](docs/path.md)

#### Replaced:
- `--kubeconfig` - use `--authentication-kubeconfig` and `--authorization-kubeconfig` instead
- `--secure-listen-address` - use a combination of `--bind-address` and `--secure-port`

#### Changes in behavior:
The proxy will now attempt to read the `kube-system/extension-apiserver-authentication` ConfigMap in order to be able to handle client certificate authentication (mTLS) via the cluster-wide trust. To prevent this, set `--authentication-skip-lookup`. If, on the other hand, this is a desirable behavior, you'll want to assign the `extension-apiserver-authentication-reader` role to the ServiceAccount running the proxy.

### Options
The kube-rbac-proxy has all [`glog`](https://github.com/golang/glog) flags for logging purposes. To use the kube-rbac-proxy there are a few flags you may want to set:

* `--upstream`: This is the upstream you want to proxy to.
* `--config-file`: This file specifies details on the SubjectAccessReview you want to be performed on a request. For example, this could contain that an entity performing a request has to be allowed to perform a `get` on the Deployment called `my-frontend-app`, as well as the ability to configure whether SubjectAccessReviews are rewritten based on requests.

See the [`examples/`](examples/) directory for the following examples:

* [non-resource-url example](examples/non-resource-url)
* [resource-attributes example](examples/resource-attributes)
* [oidc example](examples/oidc)
* [rewriting SubjectAccessReviews based on request query parameters](examples/rewrites)

All command line flags:

[embedmd]:# (_output/help.txt)
```txt
$ kube-rbac-proxy -h
The kube-rbac-proxy is a small HTTP proxy for a single upstream
that can perform RBAC authorization against the Kubernetes API using SubjectAccessReview.

Usage:
  kube-rbac-proxy [flags]

Secure serving flags:

      --bind-address ip                        The IP address on which to listen for the --secure-port port. The associated interface(s) must be reachable by the rest of the cluster, and by CLI/web clients. If blank or an unspecified address (0.0.0.0 or ::), all interfaces and IP address families will be used. (default 0.0.0.0)
      --cert-dir string                        The directory where the TLS certs are located. If --tls-cert-file and --tls-private-key-file are provided, this flag will be ignored. (default "apiserver.local.config/certificates")
      --http2-max-streams-per-connection int   The limit that the server gives to clients for the maximum number of streams in an HTTP/2 connection. Zero means to use golang's default.
      --permit-address-sharing                 If true, SO_REUSEADDR will be used when binding the port. This allows binding to wildcard IPs like 0.0.0.0 and specific IPs in parallel, and it avoids waiting for the kernel to release sockets in TIME_WAIT state. [default=false]
      --permit-port-sharing                    If true, SO_REUSEPORT will be used when binding the port, which allows more than one instance to bind on the same address and port. [default=false]
      --secure-port int                        The port on which to serve HTTPS with authentication and authorization. If 0, don't serve HTTPS at all. (default 443)
      --tls-cert-file string                   File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert). If HTTPS serving is enabled, and --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory specified by --cert-dir.
      --tls-cipher-suites strings              Comma-separated list of cipher suites for the server. If omitted, the default Go cipher suites will be used. 
                                               Preferred values: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256. 
                                               Insecure values: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_RC4_128_SHA.
      --tls-min-version string                 Minimum TLS version supported. Possible values: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13
      --tls-private-key-file string            File containing the default x509 private key matching --tls-cert-file.
      --tls-sni-cert-key namedCertKey          A pair of x509 certificate and private key file paths, optionally suffixed with a list of domain patterns which are fully qualified domain names, possibly with prefixed wildcard segments. The domain patterns also allow IP addresses, but IPs should only be used if the apiserver has visibility to the IP address requested by a client. If no domain patterns are provided, the names of the certificate are extracted. Non-wildcard matches trump over wildcard matches, explicit domain patterns trump over extracted names. For multiple key/certificate pairs, use the --tls-sni-cert-key multiple times. Examples: "example.crt,example.key" or "foo.crt,foo.key:*.foo.com,foo.com". (default [])

Delegating authentication flags:

      --authentication-kubeconfig string                  kubeconfig file pointing at the 'core' kubernetes server with enough rights to create tokenreviews.authentication.k8s.io.
      --authentication-skip-lookup                        If false, the authentication-kubeconfig will be used to lookup missing authentication configuration from the cluster.
      --authentication-token-webhook-cache-ttl duration   The duration to cache responses from the webhook token authenticator. (default 10s)
      --authentication-tolerate-lookup-failure            If true, failures to look up missing authentication configuration from the cluster are not considered fatal. Note that this can result in authentication that treats all requests as anonymous.
      --client-ca-file string                             If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.
      --requestheader-allowed-names strings               List of client certificate common names to allow to provide usernames in headers specified by --requestheader-username-headers. If empty, any client certificate validated by the authorities in --requestheader-client-ca-file is allowed.
      --requestheader-client-ca-file string               Root certificate bundle to use to verify client certificates on incoming requests before trusting usernames in headers specified by --requestheader-username-headers. WARNING: generally do not depend on authorization being already done for incoming requests.
      --requestheader-extra-headers-prefix strings        List of request header prefixes to inspect. X-Remote-Extra- is suggested. (default [x-remote-extra-])
      --requestheader-group-headers strings               List of request headers to inspect for groups. X-Remote-Group is suggested. (default [x-remote-group])
      --requestheader-username-headers strings            List of request headers to inspect for usernames. X-Remote-User is common. (default [x-remote-user])

Delegating authorization flags:

      --authorization-kubeconfig string                         kubeconfig file pointing at the 'core' kubernetes server with enough rights to create subjectaccessreviews.authorization.k8s.io.
      --authorization-webhook-cache-authorized-ttl duration     The duration to cache 'authorized' responses from the webhook authorizer. (default 10s)
      --authorization-webhook-cache-unauthorized-ttl duration   The duration to cache 'unauthorized' responses from the webhook authorizer. (default 10s)

Proxy flags:

      --allow-legacy-serviceaccount-tokens          If true, allow legacy service account tokens (without an audience). Legacy tokens are less secure and are disabled by default.
      --allow-paths strings                         Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the request doesn't match, kube-rbac-proxy responds with a 404 status code. If omitted, the incoming request path isn't checked. Cannot be used with --ignore-paths.
      --auth-header-groups-field-name string        The name of the field inside a http(2) request header to tell the upstream server about the user's groups (default "x-remote-groups")
      --auth-header-groups-field-separator string   The separator string used for concatenating multiple group names in a groups header field's value (default "|")
      --auth-header-user-field-name string          The name of the field inside a http(2) request header to tell the upstream server about the user's name (default "x-remote-user")
      --auth-token-audiences strings                Comma-separated list of token audiences to accept. Tokens must have at least one audience from this list. Must be set unless --allow-legacy-serviceaccount-tokens is true.
      --config-file string                          Configuration file to configure static and rewrites authorization of the kube-rbac-proxy.
      --disable-http2-serving                       If true, HTTP2 serving will be disabled [default=false]
      --ignore-paths strings                        Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the requst matches, it will proxy the request without performing an authentication or authorization check. Cannot be used with --allow-paths.
      --proxy-endpoints-port int                    The port to securely serve proxy-specific endpoints (such as '/healthz'). Uses the host from the '--secure-listen-address'.
      --upstream string                             The upstream URL to proxy to once requests have successfully been authenticated and authorized.
      --upstream-ca-file string                     The CA the upstream uses for TLS connection. This is required when the upstream uses TLS and its own CA certificate
      --upstream-client-cert-file string            If set, the client will be used to authenticate the proxy to upstream. Requires --upstream-client-key-file to be set, too.
      --upstream-client-key-file string             The key matching the certificate from --upstream-client-cert-file. If set, requires --upstream-client-cert-file to be set, too.
      --upstream-force-h2c                          Force h2c to communicate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only

OIDC flags:

      --oidc-ca-file string           If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.
      --oidc-groups-claim string      Identifier of groups in JWT claim, by default set to 'groups' (default "groups")
      --oidc-groups-prefix string     If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.
      --oidc-issuer string            The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).
      --oidc-required-audience aud    The audience that must appear in all incoming tokens' aud claim. Must be set if `oidc-issuer` is configured.
      --oidc-sign-alg stringArray     Supported signing algorithms, default RS256 (default [RS256])
      --oidc-username-claim string    Identifier of the user in JWT claim, by default set to 'email' (default "email")
      --oidc-username-prefix string   If provided, the username will be prefixed with this value to prevent conflicts with other authentication strategies.

Global flags:

  -h, --help                     help for kube-rbac-proxy
      --version version[=true]   --version, --version=raw prints version information and quits; --version=vX.Y.Z... sets the reported version
```

### Authorization configuration

The format of the file accepted by the `--config-file` reads as follows:
```yaml
authorization:
  static:
  - user:
      name: <string>
      groups: [ <string> ]
    verb: <string>
    namespace: <string>
    apiGroup: <string>
    resource: <string>
    subresource: <string>
    name: <string>
    resourceRequest: <bool>
    path: <string>
  resourceAttributes:
    namespace: <string>
    apiGroup: <string>
    apiVersion: <string>
    resource: <string>
    subresource: <string>
    name: <string>
  rewrites:
    byQueryParameter:
      name: <string>
    byHttpHeader:
      name: <string>
```

The `authorization.static` is a YAML list, each element contains a set of attributes. kube-rbac-proxy translates incoming requests into kube-like authorization attributes that are checked against the list. If the request matches against any of the elements of the list, access is allowed.

The `authorization.resourceAttributes` and `authorization.rewrites` set how authorization attributes retrieved from HTTP requests to the proxy should be presented in a `SubjectAccessReview` to the kube-apiserver:
 - `resourceAttributes` will set the given fields while sending the SAR to the kube-apiserver, while the keeping the `verb` and `user` based on the HTTP request
 - `rewrites` allows retrieving certain parameters from the incoming HTTP request and use them in the fields of `resourceAttributes` if these take the form of `{{ .Value }}`, thus allowing parametrization of the SAR sent to the kube-apiserver


### How to update Go dependencies

To update the Go dependencies run `make update-go-deps`.

This might be useful to do during a release.

## Why?

You may ask yourself, why not just use the Kubernetes apiserver proxy functionality? There are two reasons why this makes sense, the first is to take load off of the Kubernetes API, so it can be used for actual requests serving the cluster components, rather than in order to serve client requests. The second and more important reason is, this proxy is intended to be a sidecar that accepts incoming HTTP requests. This way, one can ensure that a request is truly authorized, instead of being able to access an application simply because an entity has network access to it.

## Motivation

I developed this proxy in order to be able to protect [Prometheus](https://prometheus.io/) metrics endpoints. In a scenario, where an attacker might obtain full control over a Pod, that attacker would have the ability to discover a lot of information about the workload as well as the current load of the respective workload. This information could originate for example from the [node-exporter](https://github.com/prometheus/node_exporter) and [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics). Both of those metric sources can commonly be found in Prometheus monitoring stacks on [Kubernetes](https://kubernetes.io/).

This project was created to specifically solve the above problem, however, I felt there is a larger need for such a proxy in general.

## How does it work?

On an incoming request, kube-rbac-proxy first figures out which user is performing the request. The kube-rbac-proxy supports using client TLS certificates, as well as tokens. In case of a client certificates, the certificate is simply validated against the configured CA. In case of a bearer token being presented, the `authentication.k8s.io` is used to perform a `TokenReview`.

Once a user has been authenticated, again the `authentication.k8s.io` is used to perform a `SubjectAccessReview`, in order to authorize the respective request, to ensure the authenticated user has the required RBAC roles.

## Notes on ServiceAccount token security

Note that when using tokens for authentication, the receiving side can use the token to impersonate the client. Only use token authentication, when the receiving side is already higher privileged or the token itself is super low privileged, such as when the only roles bound to it are for authorization purposes with this project. Passing around highly privileged tokens is a security risk, and is not recommended.

This project was built to be used to protect metrics of cluster components. These cluster components are much higher privileged than the Prometheus Pod, so if those Pods were to use the token provided by Prometheus it would actually be lower privileged. It is not recommended to use this method for non infrastructure components.

For better security properties use mTLS for authentication instead, and for user authentication, other methods have yet to be added.

## Why are NetworkPolicies not enough?

There are a couple of reasons why the existence of NetworkPolicies may not cover the same use case(s):

* NetworkPolicies are not available in all providers, installers and distros.
* NetworkPolicies do not apply to Pods with HostNetworking enabled, the use case I created this project with the Prometheus node-exporter requires this.
* Once TLS/OIDC is supported, the kube-rbac-proxy can be used to perform AuthN/AuthZ on users.

## Differentiation to [Envoy](https://www.envoyproxy.io/)/[Istio](https://istio.io/)

This projects is not intended to compete with Envoy or IstioMesh. Although on the surface they seem similar, the goals and usage complement each other. It's perfectly ok to use Envoy as the ingress point of traffic of a Pod, which then forwards traffic to the kube-rbac-proxy, which in turn then proxies to the actually serving application.

Additionally, to my knowledge Envoy neither has nor plans Kubernetes specific RBAC/AuthZ support (maybe it shouldn’t even). My knowledge may very well be incomplete, please point out if it is. After all I'm happy if I don't have to maintain more code, but as long as this serves a purpose to me and no other project can provide it, I'll maintain this.

## Testing

To run tests locally, you need to have [kind](https://kind.sigs.k8s.io/) installed. By default it uses the default cluster, so be aware that it might override your default cluster.

The command to execute the tests is: `VERSION=local make clean container kind-create-cluster test`.

## Roadmap

PRs are more than welcome!

* Tests
