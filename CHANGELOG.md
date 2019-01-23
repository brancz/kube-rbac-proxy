## Next release

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
