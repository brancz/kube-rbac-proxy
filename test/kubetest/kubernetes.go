/*
Copyright 2017 Frederic Branczyk All rights reserved.

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
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

const DefaultTimeout = 60 * time.Second

func CreatedManifests(client kubernetes.Interface, paths ...string) Setup {
	return func(ctx *ScenarioContext) error {
		for _, path := range paths {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			if len(content) == 0 {
				return fmt.Errorf("manifest has no content: %s", path)
			}

			var meta metav1.TypeMeta
			if err = yaml.Unmarshal(content, &meta); err != nil {
				return err
			}

			// TODO: This needs to be more generic!

			kind := strings.ToLower(meta.Kind)
			switch kind {
			case "clusterrole":
				if err := createClusterRole(client, ctx, content); err != nil {
					return err
				}
			case "clusterrolebinding":
				if err := createClusterRoleBinding(client, ctx, content); err != nil {
					return err
				}
			case "deployment":
				if err := createDeployment(client, ctx, content); err != nil {
					return err
				}
			case "service":
				if err := createService(client, ctx, content); err != nil {
					return err
				}
			case "serviceaccount":
				if err := createServiceAccount(client, ctx, content); err != nil {
					return err
				}
			case "secret":
				if err := createSecret(client, ctx, content); err != nil {
					return err
				}
			case "configmap":
				if err := createConfigmap(client, ctx, content); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unable to unmarshal manifest with unknown kind: %s", kind)
			}
		}
		return nil
	}
}

func createClusterRole(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var cr *rbacv1.ClusterRole
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&cr); err != nil {
		return err
	}

	roleCtx, roleCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer roleCancel()
	_, err := client.RbacV1().ClusterRoles().Create(roleCtx, cr, metav1.CreateOptions{})

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer finalizerCancel()
		return client.RbacV1().ClusterRoles().Delete(finalizerCtx, cr.Name, metav1.DeleteOptions{})
	})

	return err
}

func createClusterRoleBinding(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var crb *rbacv1.ClusterRoleBinding
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&crb); err != nil {
		return err
	}

	rolebindingCtx, rolebindingCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer rolebindingCancel()
	_, err := client.RbacV1().ClusterRoleBindings().Create(rolebindingCtx, crb, metav1.CreateOptions{})

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer finalizerCancel()
		return client.RbacV1().ClusterRoleBindings().Delete(finalizerCtx, crb.Name, metav1.DeleteOptions{})
	})

	return err
}

func createDeployment(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var d appsv1.Deployment
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&d); err != nil {
		return err
	}

	d.Namespace = ctx.Namespace

	createDeploymentCtx, createDeploymentCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer createDeploymentCancel()
	_, err := client.AppsV1().Deployments(d.Namespace).Create(createDeploymentCtx, &d, metav1.CreateOptions{})

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), 2 * DefaultTimeout)
		defer finalizerCancel()
		dep, err := client.AppsV1().Deployments(d.Namespace).Get(finalizerCtx, d.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		sel, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
		if err != nil {
			return err
		}

		dumpLogs(client, ctx, metav1.ListOptions{LabelSelector: sel.String()})

		err = client.AppsV1().Deployments(dep.Namespace).Delete(finalizerCtx, dep.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}

		return PodsAreGone(client, sel.String())(ctx)
	})

	return err
}

func dumpLogs(client kubernetes.Interface, ctx *ScenarioContext, opts metav1.ListOptions) {
	dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 2 * DefaultTimeout)
	defer dumpCancel()
	pods, err := client.CoreV1().Pods(ctx.Namespace).List(dumpCtx, opts)
	if err != nil {
		return
	}

	for _, p := range pods.Items {
		for _, c := range p.Spec.Containers {
			fmt.Println("=== LOGS", ctx.Namespace, p.Name, c.Name)

			rest := client.CoreV1().Pods(ctx.Namespace).GetLogs(p.GetName(), &corev1.PodLogOptions{
				Container: c.Name,
				Follow:    false,
			})

			stream, err := rest.Stream(dumpCtx)
			if err != nil {
				return
			}

			io.Copy(os.Stdout, stream)
		}
	}
}

func createService(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var s *corev1.Service
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&s); err != nil {
		return err
	}

	s.Namespace = ctx.Namespace

	serviceCtx, serviceCancel := context.WithTimeout(context.Background(), 120 * time.Second)
	defer serviceCancel()
	_, err := client.CoreV1().Services(s.Namespace).Create(serviceCtx, s, metav1.CreateOptions{})

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer finalizerCancel()
		return client.CoreV1().Services(s.Namespace).Delete(finalizerCtx, s.Name, metav1.DeleteOptions{})
	})

	return err
}

func createServiceAccount(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var sa *corev1.ServiceAccount
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&sa); err != nil {
		return err
	}

	sa.Namespace = ctx.Namespace

	serviceAccountCtx, serviceAccountCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer serviceAccountCancel()
	_, err := client.CoreV1().ServiceAccounts(sa.Namespace).Create(serviceAccountCtx, sa, metav1.CreateOptions{})

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer finalizerCancel()
		return client.CoreV1().ServiceAccounts(sa.Namespace).Delete(finalizerCtx, sa.Name, metav1.DeleteOptions{})
	})

	return err
}

func createSecret(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var secret *corev1.Secret
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&secret); err != nil {
		return err
	}

	secret.Namespace = ctx.Namespace

	createSecretCtx, createSecretCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer createSecretCancel()
	_, err := client.CoreV1().Secrets(secret.Namespace).Create(createSecretCtx, secret, metav1.CreateOptions{})

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer finalizerCancel()
		return client.CoreV1().Secrets(secret.Namespace).Delete(finalizerCtx, secret.Name, metav1.DeleteOptions{})
	})

	return err
}

func createConfigmap(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var configmap *corev1.ConfigMap
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&configmap); err != nil {
		return err
	}

	configmap.Namespace = ctx.Namespace

	createConfigmapCtx, createConfigmapCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer createConfigmapCancel()
	_, err := client.CoreV1().ConfigMaps(configmap.Namespace).Create(createConfigmapCtx, configmap, metav1.CreateOptions{})

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer finalizerCancel()
		return client.CoreV1().ConfigMaps(configmap.Namespace).Delete(finalizerCtx, configmap.Name, metav1.DeleteOptions{})
	})

	return err
}

// PodsAreReady waits for a number if replicas matching the given labels to be ready.
// Returns a func directly (not Setup or Conditions) as it can be used in Given and When steps
func PodsAreReady(client kubernetes.Interface, replicas int, labels string) func(*ScenarioContext) error {
	return func(ctx *ScenarioContext) error {
		return wait.Poll(time.Second, time.Minute, func() (bool, error) {
			listPodsCtx, listPodsCancel := context.WithTimeout(context.Background(), DefaultTimeout)
			defer listPodsCancel()
			list, err := client.CoreV1().Pods(ctx.Namespace).List(listPodsCtx, metav1.ListOptions{
				LabelSelector: labels,
			})
			if err != nil {
				return false, fmt.Errorf("failed to list pods: %v", err)
			}

			runningAndReady := 0
			for _, p := range list.Items {
				isRunningAndReady, err := podRunningAndReady(p)
				if err != nil {
					return false, err
				}

				if isRunningAndReady {
					runningAndReady++
				}
			}

			if runningAndReady == replicas {
				return true, nil
			}
			return false, nil
		})
	}
}

// PodsAreGone waits for pods being gone for the given labels.
// Returns a func directly (not Setup or Conditions) as it can be used in Given and When steps
func PodsAreGone(client kubernetes.Interface, labels string) func(*ScenarioContext) error {
	return func(ctx *ScenarioContext) error {
		return wait.Poll(time.Second, time.Minute, func() (bool, error) {
			listPodsCtx, listPodsCancel := context.WithTimeout(context.Background(), DefaultTimeout)
			defer listPodsCancel()
			list, err := client.CoreV1().Pods(ctx.Namespace).List(listPodsCtx, metav1.ListOptions{
				LabelSelector: labels,
			})

			if err != nil {
				return false, fmt.Errorf("failed to list pods: %v", err)
			}

			return len(list.Items) == 0, nil
		})
	}
}

// ServiceIsReady waits for given service to exist and have at least 1 endpoint.
// Returns a func directly (not Setup or Conditions) as it can be used in Given and When steps
func ServiceIsReady(client kubernetes.Interface, service string) func(*ScenarioContext) error {
	return func(ctx *ScenarioContext) error {
		return wait.Poll(time.Second, time.Minute, func() (bool, error) {
			reqCtx, reqCancel := context.WithTimeout(context.Background(), 2 * DefaultTimeout)
			defer reqCancel()
			_, err := client.CoreV1().Services(ctx.Namespace).Get(reqCtx, service, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to get service: %v", err)
			}

			endpoints, err := client.CoreV1().Endpoints(ctx.Namespace).Get(reqCtx, service, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to get endpoints: %v", err)
			}

			amount := 0
			for _, s := range endpoints.Subsets {
				amount = amount + len(s.Addresses)
			}
			if amount >= 1 {
				return true, nil
			}

			return false, nil
		})
	}
}

// podRunningAndReady returns whether a pod is running and each container has
// passed it's ready state.
func podRunningAndReady(pod corev1.Pod) (bool, error) {
	switch pod.Status.Phase {
	case corev1.PodFailed, corev1.PodSucceeded:
		return false, fmt.Errorf("pod completed")
	case corev1.PodRunning:
		for _, cond := range pod.Status.Conditions {
			if cond.Type != corev1.PodReady {
				continue
			}
			return cond.Status == corev1.ConditionTrue, nil
		}
		return false, fmt.Errorf("pod ready condition not found")
	}
	return false, nil
}

func Sleep(d time.Duration) Condition {
	return func(ctx *ScenarioContext) error {
		time.Sleep(d)
		return nil
	}
}

type RunOptions struct {
	ServiceAccount     string
	TokenAudience      string
	ClientCertificates bool
}

func RunSucceeds(client kubernetes.Interface, image string, name string, command []string, opts *RunOptions) Check {
	return func(ctx *ScenarioContext) error {
		return run(client, ctx, image, name, command, opts)
	}
}

func RunFails(client kubernetes.Interface, image string, name string, command []string, opts *RunOptions) Check {
	return func(ctx *ScenarioContext) error {
		err := run(client, ctx, image, name, command, opts)
		if err == nil {
			return fmt.Errorf("expected run to fail")
		}
		if err != errRun {
			return err
		}
		return nil
	}
}

var errRun = fmt.Errorf("failed to run")

// run the command and return the Check with the container's logs
func run(client kubernetes.Interface, ctx *ScenarioContext, image string, name string, command []string, opts *RunOptions) error {
	labels := map[string]string{
		"app": name,
	}
	pod := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers: []corev1.Container{{
				Name:    name,
				Image:   image,
				Command: command,
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	if opts != nil && opts.ServiceAccount != "" {
		pod.Spec.ServiceAccountName = opts.ServiceAccount
	}
	if opts != nil && opts.TokenAudience != "" {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "requestedtoken",
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Audience: opts.TokenAudience,
							Path:     "requestedtoken",
						},
					}},
				},
			},
		})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "requestedtoken",
				MountPath: "/var/run/secrets/tokens",
			},
		)
	}

	if opts != nil && opts.ClientCertificates {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "clientcertificates",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "kube-rbac-proxy-client-certificates",
				},
			},
		})

		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "clientcertificates",
				MountPath: "/certs",
			},
		)
	}

	parallelism := int32(1)
	completions := int32(1)
	activeDeadlineSeconds := int64(60)
	backoffLimit := int32(10)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kube-rbac-proxy-client-",
			Namespace:    ctx.Namespace,
		},
		Spec: batchv1.JobSpec{
			Parallelism:           &parallelism,
			Completions:           &completions,
			ActiveDeadlineSeconds: &activeDeadlineSeconds,
			BackoffLimit:          &backoffLimit,
			Template:              pod,
		},
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 2 * DefaultTimeout)
	defer cancel()

	batch, err := client.BatchV1().Jobs(ctx.Namespace).Create(reqCtx, job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create job: %v", err)
	}

	ctx.AddFinalizer(func() error {
		finalizerCtx, finalizerCancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer finalizerCancel()
		err := client.BatchV1().Jobs(ctx.Namespace).Delete(finalizerCtx, batch.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete job: %v", err)
		}

		return nil
	})

	watch, err := client.BatchV1().Jobs(ctx.Namespace).Watch(reqCtx, metav1.SingleObject(batch.ObjectMeta))
	if err != nil {
		return fmt.Errorf("failed to watch job: %v", err)
	}

	for event := range watch.ResultChan() {
		job := event.Object.(*batchv1.Job)
		conditions := job.Status.Conditions

		failed := false
		for _, c := range conditions {
			if c.Type == batchv1.JobFailed {
				failed = c.Status == corev1.ConditionTrue
			}
		}

		if failed {
			dumpLogs(client, ctx, metav1.ListOptions{LabelSelector: "job-name=" + batch.Name})
			return errRun
		}

		complete := false
		for _, c := range conditions {
			if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
				complete = true
			}
		}
		if complete && !failed {
			dumpLogs(client, ctx, metav1.ListOptions{LabelSelector: "job-name=" + batch.Name})
			return nil
		}
	}

	return nil
}

func CreateNamespace(client kubernetes.Interface, name string) error {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	reqCtx, reqCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer reqCancel()

	_, err := client.CoreV1().Namespaces().Create(reqCtx, ns, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create namespace with name %v", name)
	}
	return nil
}

func DeleteNamespace(client kubernetes.Interface, name string) error {
	reqCtx, reqCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer reqCancel()
	return client.CoreV1().Namespaces().Delete(reqCtx, name, metav1.DeleteOptions{})
}
