# Minikube + RBAC

To start [minikube](https://github.com/kubernetes/minikube) with RBAC enabled run it with the `--extra-config=apiserver.Authorization.Mode=RBAC` flag:

```bash
$ minikube start --extra-config=apiserver.Authorization.Mode=RBAC
Starting local Kubernetes v1.8.0 cluster...
Starting VM...
Getting VM IP address...
Moving files into cluster...
Setting up certs...
Connecting to cluster...
Setting up kubeconfig...
Starting cluster components...
Kubectl is now configured to use the cluster.
Loading cached images from config file.
```

When minikube is started with this flag it does not handle RBAC for addons, so that needs to be fixed.

```bash
$ kubectl apply -f minikube-rbac-fix.yaml
clusterrole "cluster-writer" created
clusterrole "cluster-reader" created
clusterrolebinding "cluster-write" created
clusterrolebinding "cluster-read" created
rolebinding "sd-build-write" created
```

Ensure that everything is running as expected:

```bash
$ kubectl get pods --namespace=kube-system
NAME                          READY     STATUS    RESTARTS   AGE
kube-addon-manager-minikube   1/1       Running   0          8m
kube-dns-86f6f55dd5-lncvt     3/3       Running   0          51s
storage-provisioner           1/1       Running   0          8m
```

