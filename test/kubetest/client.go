package kubetest

import "k8s.io/client-go/kubernetes"

func ClientSucceeds(client kubernetes.Interface, command string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		return RunSucceeds(
			client,
			"quay.io/brancz/krp-curl:v0.0.2",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", command},
			opts,
		)(ctx)
	}
}

func ClientFails(client kubernetes.Interface, command string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		return RunFails(
			client,
			"quay.io/brancz/krp-curl:v0.0.2",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", command},
			opts,
		)(ctx)
	}
}
