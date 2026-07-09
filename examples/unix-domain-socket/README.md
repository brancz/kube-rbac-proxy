# Unix Domain Socket Upstream Example

This example demonstrates how to use kube-rbac-proxy with an upstream application that listens on a Unix domain socket instead of a TCP port.

Using a Unix domain socket for the upstream connection provides several benefits:

- **No port conflicts** — the upstream doesn't need to bind a TCP port in the pod.
- **Filesystem-level access control** — socket permissions limit which processes can connect.
- **No network exposure** — the upstream is never reachable over TCP, even on localhost.

## How it works

Both containers in the pod share an `emptyDir` volume mounted at `/sockets`. The upstream application creates its socket at `/sockets/app.sock`, and kube-rbac-proxy connects to it using the `unix://` scheme:

```
--upstream=unix:///sockets/app.sock
```

The format is `unix://<socket-path>` or `unix://<socket-path>:<http-path-prefix>`. The `:<http-path-prefix>` portion is optional and defaults to `/`.

## Deploy

```bash
kubectl create -f deployment.yaml
```

The deployment creates:

- A `ServiceAccount` and RBAC for kube-rbac-proxy to perform TokenReviews and SubjectAccessReviews.
- A `Service` exposing port 8443.
- A `Deployment` with two containers sharing the socket volume:
  - **kube-rbac-proxy** — listens on `0.0.0.0:8443` (TLS), proxies authenticated requests to the unix socket.
  - **upstream** — a simple app that listens on `unix:///sockets/app.sock` and serves Prometheus metrics at `/metrics`.

The upstream app source is in the `upstream/` directory.

## Test

Grant the default service account access to `/metrics`, then run a curl job:

```bash
kubectl create -f client-rbac.yaml -f client.yaml
```

Check the logs:

```bash
kubectl logs job/krp-curl
```

You should see a successful 200 response with Prometheus metrics from the upstream app.
