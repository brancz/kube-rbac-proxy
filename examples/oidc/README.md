# OIDC authentication

Note to try this out with minikube, make sure you enable RBAC correctly as explained [here](../minikube-rbac/README.md)

Kubernetes supports OIDC authentication natively, configured via API server flags. In this case, a request contains the OIDC ID token in its bearer header. The token is then used for token review by the Kubernetes API. This already works with the existing kube-rbac-proxy functionality. The resulting metadata (user and/or group information) is then passed to the subject review Kubernetes API for authorization.

If Kubernetes is not configured to use OIDC and changes to the API server are not possible (i.e. in 3rd party or restricted environments), kube-rbac-proxy can be configured to authenticate the request against OIDC itself. In this case, the token review functionality of Kubernetes is omitted. As above the resulting metadata is still passed to the subject review Kubernetes API for authorization.

Like in other examples, `kube-rbac-proxy` also requires RBAC access to perform SubjectAccessReviews.

```bash
$ kubectl create -f deployment.yaml
```
```bash
$ kubectl create -f configmap.yaml
```

```bash
$ kubectl create -f client-rbac.yaml
```

Note: The {ISSUER} and {CLIENT_ID} in the deployment have to be replaced with the issuer and client in the OIDC provider configuration.
