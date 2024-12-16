/*
Copyright 2024 the kube-rbac-proxy maintainers. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package kubetest

import (
	"context"
	"fmt"
	"io"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"net/http"
	"time"
)

// findPodByAppName attempts lookup a Pod using its app=X label
func findPodByAppName(client kubernetes.Interface, namespace, name string) (*corev1.Pod, error) {
	pods, err := client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", name),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods matching app=%s: %w", name, err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("failed to find pod matching app=%s", name)
	}

	return &pods.Items[0], nil
}

// CreatePortForwarder creates a port forwarder session from a local port to a Pod so that the test infrastructure can
// invoke API endpoint directly if necessary.
func CreatePortForwarder(client kubernetes.Interface, config *rest.Config, podName string, localPort, remotePort int) Action {
	return func(ctx *ScenarioContext) error {
		pod, err := findPodByAppName(client, ctx.Namespace, podName)
		if err != nil {
			return fmt.Errorf("failed to find pod matching app=%s: %w", podName, err)
		}

		restClient := client.CoreV1().RESTClient()
		url := restClient.
			Post().
			Resource("pods").
			Namespace(ctx.Namespace).
			Name(pod.Name).
			SubResource("portforward").
			URL()

		transport, upgrader, err := spdy.RoundTripperFor(config)
		if err != nil {
			return fmt.Errorf("could not create roundtripper: %w", err)
		}

		stopCh := make(chan struct{}, 1)
		readyCh := make(chan struct{}, 1)

		dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)
		forwarder, err := portforward.New(dialer, []string{fmt.Sprintf("%d:%d", localPort, remotePort)}, stopCh, readyCh, io.Discard, io.Discard)
		if err != nil {
			return fmt.Errorf("could not create forwarder: %w", err)
		}
		go func() {
			err := forwarder.ForwardPorts()
			if err != nil {
				fmt.Println("failed to forward ports: ", err)
				return
			}
		}()

		ctx.AddCleanUp(func() error { stopCh <- struct{}{}; return nil })

		// Wait for the forwarder to become ready
		timeoutCh := time.After(30 * time.Second)
		select {
		case <-timeoutCh:
			return fmt.Errorf("timed out waiting for port forwarder")
		case <-readyCh:
			return nil
		}
	}
}
