## 0.19.1 / 2025-04-23

- [ENHANCEMENT] Bump deps
- [BUGFIX] Fix nil-pointer dereference in OIDC authenticator

## 0.19.0 / 2025-02-14

- [ENHANCEMENT] Bump deps
- [ENHANCEMENT] OIDC authenticator defaults to using host's root CA pool if CA file is not provided

## 0.18.2 / 2024-11-29

- [BUGFIX] Mask tokens even in the high verbosity in logs
- [ENHANCEMENT] Bump deps

## 0.18.1 / 2024-06-05

- [ENHANCEMENT] Bump deps, in particular go-jose and golang (->CVE) and k8s (v1.31)

## 0.18.0 / 2024-06-05

- [ENHANCEMENT] Bump deps, in particular otel (>CVE) and k8s (v1.30)
- [ENHANCEMENT] Add OIDC username prefix, which was missing

## 0.17.1 / 2024-05-07

- [BUGFIX] make deprecated (usptream removed) flags behave like before

## 0.17.0 / 2024-02-08

- [ENHANCEMENT] add command-line args --kube-api-qps/--kube-api-burst
- [ENHANCEMENT] Bump deps

## 0.16.0 / 2024-02-08

- [ENHANCEMENT] Bump dependencies and in particular to kubernetes to v1.28
- [CHANGE] Due to the bump to k8s v1.28 some logging flags are disabled

## 0.15.0 / 2023-10-20

- [ENHANCEMENT] bump opentelemetry to fix CVE
- [ENHANCEMENT] add option to disable HTTP/2: `--http2-disable` (default: `false`)
- [ENHANCEMENT] add option to fine-tune HTTP/2:
    - `--http2-max-size` (default: 256kb)
    - `--http2-max-concurrent-streams` (default: 100)

## 0.14.4 / 2023-10-16

- [ENHANCEMENT] bump golang and x/net

## 0.14.3 / 2023-09-07

- [BUGFIX] `--version` returns now the proper kube-rbac-proxy version
- [ENHANCEMENT] bump dependencies

## 0.14.2 / 2023-06-05

- [ENHANCEMENT] bump dependencies
- [ENHANCEMENT] Makefile, Dockerfile to work better with different architectures

## 0.14.1 / 2023-04-06

- [ENHANCEMENT] bump dependencies

## 0.14.0 / 2022-12-15

* [ENHANCEMENT] `README.md` now contains information about the future outlook of the project wrt to deprecations, features and K8s Sig-Auth acceptance
* [ENHANCEMENT] bump dependencies
* [FEATURE] health endpoint `/healthz` offered on `--proxy-endpoints-port`
* [FEATURE] `--upstream-client-cert-file` enables the kube-rbac-proxy client connecting to upstream to use TLS
* [CHANGE] use cobra and usptream command machinery, introduces deprecation to some flags

## 0.13.1 / 2022-10-04

* [ENHANCEMENT] bump k8s to 1.25.2 #200 (contains fixes for CVEs)
* [ENHANCEMENT] bump Go to 1.19.1 #178 (contains fixes for CVEs)
* [ENHANCEMENT] bump golang.org/x/crypto due to CVE-2022-27191 #188
* [CHANGE] add warning messages for features that will be removed

## 0.13.0 / 2022-06-29

* [ENHANCEMENT] bump k8s to 1.24.2 #178
* [ENHANCEMENT] bump Go to 1.18.3 #178
* [ENHANCEMENT] update README.md to be more accurate and up to date #178, #173
* [ENHANCEMENT] check all headers for rewrites and create additional authz requests #171

## 0.12.0 / 2022-04-08

* [ENHANCEMENT] bump k8s to 1.23.5. #149, #155, #160
* [ENHANCEMENT] add release documentation, #156
* [ENHANCEMENT] use supported apiVersion for deployment and authorization. #150
* [BUGFIX] ppc64le image build which in turn fixed multi-arch build. #147
* [ENHANCEMENT] Support building on riscv64 architecture. #141
* [ENHANCEMENT] move --upstream-force-h2c out of --insecure-listen-address. #140

## 0.11.0 / 2021-08-02

* [FEATURE] Support for path patterns in --allow-paths and --ignore-paths. #135
* [ENHANCEMENT] Dynamically reload client CA. #127
* [BUGFIX] Fix panics on client-cert authenticated requests. #132

## 0.10.0 / 2021-05-07

* [FEATURE] Support local static authorizer. #125

## 0.9.0 / 2021-04-27

* [FEATURE] Support rewrites using HTTP headers in addition to query parameters. #104
* [FEATURE] Support pass-through of client certificates. #113
* [FEATURE] Support TLS 1.3. #120

## 0.8.0 / 2020-11-03

* [FEATURE] Add ability with the new `--ignore-paths` flag to define paths for which kube-rbac-proxy will proxy without performing authn/authz. This cannot be used with `--allow-paths`. #91

## 0.7.0 / 2020-09-15

* [CHANGE] Make images rootless. #86
* [FEATURE] Add ability to check for allowed request paths with new `--allow-paths` config option. #83

## 0.6.0 / 2020-06-11

* [CHANGE] Use gcr.io/distroless/static as base image instead of alpine. #67
* [ENHANCEMENT] Add multi-arch container images for amd64, arm, arm64, ppc64le and s390x. #67

## 0.5.0 / 2020-02-17

* [CHANGE] Move from glog to klog for logging. #57
* [FEATURE] Support token audience reviews. #56
* [FEATURE] Support custom upstream CAs. #34
* [ENHANCEMENT] Reload TLS certificates at runtime. #47
* [ENHANCEMENT] Add host in self-signed certs. #43

## 0.4.1 / 2019-01-23

* [ENHANCEMENT] Use golang.org/x/net http2 server. #29
* [ENHANCEMENT] Update Kubernetes to 1.13.2 #28
* [ENHANCEMENT] Make multi-arch builds possible. #21
* [BUGFIX] Log when server isn't able to start. #27
* [BUGFIX] Set user specified TLS configuration when explicit TLS certificates are provided.

## 0.4.0 / 2018-10-24

* [CHANGE] The config file flag has been renamed to `--config-file`.
* [CHANGE] There is a breaking change in the configuration. All configuration that was previously valid, is now nested in `.authorization.resourceAttributes`.
* [FEATURE] Add OIDC token authentication provider (note: this is not a client code flow for client authentication).
* [FEATURE] Add ability to rewrite SubjectAccessReviews based on request query parameters.

## 0.3.1 / 2018-06-20

This release is unmodified code from v0.3.0, but built with latest golang.

* [BUGFIX] Fix `x509: cannot parse dnsName` in intermediate certificates.

## 0.3.0 / 2018-03-27

* [FEATURE] Add HTTP/2 support.
* [ENHANCEMENT] Add ability to choose TLS cipher suites.
* [ENHANCEMENT] Add ability to choose minimum TLS version and default to TLS 1.2.

## 0.2.0 / 2018-01-03

* [CHANGE] `--listen-address` flag renamed to `--insecure-listen-address`.
* [FEATURE] Add TLS support.
