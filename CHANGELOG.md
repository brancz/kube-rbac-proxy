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
