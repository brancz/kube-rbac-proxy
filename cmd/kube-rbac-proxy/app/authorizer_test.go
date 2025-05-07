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

package app

import (
	"context"
	"fmt"
	"testing"

	userInfo "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

func TestAuthorizerSetup(t *testing.T) {
	pathConfigInput := []string{"/metrics"}
	defaultUserName := "test-user"
	resourceConfigInput := &rewrite.ResourceAttributes{
		Namespace:  "resource-attributes-namespace",
		APIGroup:   "",
		APIVersion: "v1",
		Resource:   "pods",
		Name:       "my-pod",
	}
	staticConfigInput := []static.StaticAuthorizationConfig{
		{
			User:            static.UserConfig{Name: defaultUserName},
			ResourceRequest: true,
			Resource:        "pods",
			Namespace:       "static-namespace",
			Verb:            "get",
		},
	}

	resourceConfigAuthorizer := makeAuthorizer(func(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		switch {
		case a.GetNamespace() != resourceConfigInput.Namespace:
			return authorizer.DecisionDeny, "", fmt.Errorf("wrong namespace: have %q, want %q", a.GetNamespace(), resourceConfigInput.Namespace)
		case a.GetAPIGroup() != resourceConfigInput.APIGroup:
			return authorizer.DecisionDeny, "", fmt.Errorf("wrong API group: have %q, want %q", a.GetAPIGroup(), resourceConfigInput.APIGroup)
		case a.GetAPIVersion() != resourceConfigInput.APIVersion:
			return authorizer.DecisionDeny, "", fmt.Errorf("wrong API version: have %q, want %q", a.GetAPIVersion(), resourceConfigInput.APIVersion)
		case a.GetResource() != resourceConfigInput.Resource:
			return authorizer.DecisionDeny, "", fmt.Errorf("wrong resource: have %q, want %q", a.GetResource(), resourceConfigInput.Resource)
		case a.GetName() != resourceConfigInput.Name:
			return authorizer.DecisionDeny, "", fmt.Errorf("wrong name: have %q, want %q", a.GetName(), resourceConfigInput.Name)
		case a.GetUser().GetName() != defaultUserName:
			return authorizer.DecisionDeny, "", fmt.Errorf("wrong user: have %q, want %q", a.GetUser().GetName(), defaultUserName)
		}
		return authorizer.DecisionAllow, "", nil
	})

	emptyConfig := NewConfigBuilder().Build()
	pathOnlyConfig := NewConfigBuilder().WithPaths(pathConfigInput).Build()
	staticOnlyConfig := NewConfigBuilder().WithStatic(staticConfigInput).Build()
	resourceOnlyConfig := NewConfigBuilder().
		WithResourceAttributesRewrite(resourceConfigInput).
		Build()
	pathAndStaticConfig := NewConfigBuilder().
		WithPaths(pathConfigInput).
		WithStatic(staticConfigInput).
		Build()
	rewriteAndStaticConfig := NewConfigBuilder().
		WithResourceAttributesRewrite(resourceConfigInput).
		WithStatic(staticConfigInput).
		Build()
	pathAndRewriteAndStaticConfig := NewConfigBuilder().
		WithPaths(pathConfigInput).
		WithResourceAttributesRewrite(resourceConfigInput).
		WithStatic(staticConfigInput).
		Build()

	for _, testCase := range []struct {
		name       string
		attributes authorizer.Attributes
		expected   map[*server.KubeRBACProxyInfo]authorizer.Decision
	}{
		{
			name: "good path attributes",
			attributes: authorizer.AttributesRecord{
				Path: "/metrics",
			},
			expected: map[*server.KubeRBACProxyInfo]authorizer.Decision{
				emptyConfig:                   authorizer.DecisionNoOpinion,
				pathOnlyConfig:                authorizer.DecisionAllow,
				staticOnlyConfig:              authorizer.DecisionNoOpinion,
				pathAndStaticConfig:           authorizer.DecisionAllow,
				rewriteAndStaticConfig:        authorizer.DecisionDeny, // rewrite makes it stricter
				pathAndRewriteAndStaticConfig: authorizer.DecisionAllow,
			},
		},
		{
			name: "bad path attributes",
			attributes: authorizer.AttributesRecord{
				Path: "/admin",
			},
			expected: map[*server.KubeRBACProxyInfo]authorizer.Decision{
				emptyConfig:                   authorizer.DecisionNoOpinion,
				pathOnlyConfig:                authorizer.DecisionNoOpinion,
				staticOnlyConfig:              authorizer.DecisionNoOpinion,
				pathAndStaticConfig:           authorizer.DecisionNoOpinion,
				rewriteAndStaticConfig:        authorizer.DecisionDeny, // rewrite makes it stricter
				pathAndRewriteAndStaticConfig: authorizer.DecisionDeny, // rewrite makes it stricter
			},
		},
		{
			name: "matches static attributes",
			attributes: authorizer.AttributesRecord{
				User:            &userInfo.DefaultInfo{Name: "test-user"},
				ResourceRequest: true,
				Resource:        "pods",
				Namespace:       "static-namespace",
				Verb:            "get",
			},
			expected: map[*server.KubeRBACProxyInfo]authorizer.Decision{
				emptyConfig:                   authorizer.DecisionNoOpinion,
				pathOnlyConfig:                authorizer.DecisionNoOpinion,
				staticOnlyConfig:              authorizer.DecisionAllow,
				pathAndStaticConfig:           authorizer.DecisionAllow,
				rewriteAndStaticConfig:        authorizer.DecisionDeny, // rewrite messes with our attributes
				pathAndRewriteAndStaticConfig: authorizer.DecisionDeny, // rewrite messes with our attributes
			},
		},
	} {
		for _, testConfig := range []struct {
			name  string
			cfg   *server.KubeRBACProxyInfo
			authz authorizer.Authorizer
		}{
			{
				name: "empty config",
				cfg:  emptyConfig,
			},
			{
				name: "path only config",
				cfg:  pathOnlyConfig,
			},
			{
				name: "static only config",
				cfg:  staticOnlyConfig,
			},
			{
				name:  "rewrite only config",
				cfg:   resourceOnlyConfig,
				authz: resourceConfigAuthorizer,
			},
			{
				name: "path and static config",
				cfg:  pathAndStaticConfig,
			},
			{
				name: "rewrite and static config",
				cfg:  rewriteAndStaticConfig,
			},
			{
				name: "path and rewrite and static config",
				cfg:  pathAndRewriteAndStaticConfig,
			},
		} {
			t.Run(testCase.name+" with "+testConfig.name, func(t *testing.T) {
				if testConfig.authz == nil {
					testConfig.authz = authorizerfactory.NewAlwaysDenyAuthorizer()
				}

				decision, _, err := getAuthorizerFunc(
					t, testConfig.cfg, testConfig.authz,
				)(context.Background(), testCase.attributes)

				if expectedDecision, ok := testCase.expected[testConfig.cfg]; ok {
					if err != nil {
						t.Fatalf("expected no error, got %v", err)
					}
					if decision != expectedDecision {
						t.Errorf("expected decision %q, got %q", decisionToString(expectedDecision), decisionToString(decision))
					}
					return
				}

				// We expect this to fail.
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
			})
		}
	}
}
