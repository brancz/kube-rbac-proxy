/*
Copyright 2025 the kube-rbac-proxy maintainers. All rights reserved.

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

package testtemplates

import (
	"bytes"
	"embed"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"
)

//go:embed data/*
var testTemplates embed.FS

func GetKRPDeploymentTemplate() *appsv1.Deployment {
	return Read[appsv1.Deployment]("data/deployment.yaml")
}

func GetKRPService() *corev1.Service {
	return Read[corev1.Service]("data/service.yaml")
}

func GetKRPAuthDelegatorRole() *rbacv1.ClusterRole {
	return Read[rbacv1.ClusterRole]("data/auth-delegator-clusterrole.yaml")
}

func GetMetricsRoleForClient() *rbacv1.ClusterRole {
	return Read[rbacv1.ClusterRole]("data/metrics-clusterrole.yaml")
}

func Read[T any](path string) *T {
	data, err := testTemplates.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read template %s: %v", path, err))
	}

	ret, err := decodeFromBytes[T](data)
	if err != nil {
		var dstType T
		panic(fmt.Sprintf("failed to decode template for %T: %v", dstType, err))
	}

	return ret
}

func decodeFromBytes[T any](data []byte) (*T, error) {
	var ret = new(T)

	src := bytes.NewReader(data)

	err := kubeyaml.NewYAMLOrJSONDecoder(src, src.Len()).Decode(ret)
	return ret, err
}
