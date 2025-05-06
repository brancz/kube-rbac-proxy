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
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	serverconfig "k8s.io/apiserver/pkg/server"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/path"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

// setupAuthorizer runs different authorization checks based on the configuration.
func setupAuthorizer(krbInfo *server.KubeRBACProxyInfo, delegatedAuthz *serverconfig.AuthorizationInfo) (authorizer.Authorizer, error) {
	// authz are running after the pathAuthorizer
	// and after the attributes have been rewritten.
	// Default k8s authorizer
	authz := delegatedAuthz.Authorizer

	// Static authorization authorizes against a static file is ran before the SubjectAccessReview.
	if krbInfo.Authorization.Static != nil {
		staticAuthorizer, err := static.NewStaticAuthorizer(krbInfo.Authorization.Static)
		if err != nil {
			return nil, fmt.Errorf("failed to create static authorizer: %w", err)
		}

		authz = union.New(staticAuthorizer, authz)
	}

	// Rewriting attributes such that they fit the given use-case.
	var attrsGenerator rewrite.AttributesGenerator
	switch {
	case krbInfo.Authorization.ResourceAttributes != nil && krbInfo.Authorization.Rewrites == nil:
		attrsGenerator = rewrite.NewResourceAttributesGenerator(
			krbInfo.Authorization.ResourceAttributes,
		)
	case krbInfo.Authorization.ResourceAttributes != nil && krbInfo.Authorization.Rewrites != nil:
		attrsGenerator = rewrite.NewTemplatedResourceAttributesGenerator(
			krbInfo.Authorization.ResourceAttributes,
		)
	default:
		attrsGenerator = &rewrite.NonResourceAttributesGenerator{}
	}

	if attrsGenerator != nil {
		authz = rewrite.NewRewritingAuthorizer(
			authz,
			attrsGenerator,
		)
	}

	// pathAuthorizer is running before any other authorizer.
	// It works outside of the default authorizers.
	var pathAuthorizer authorizer.Authorizer
	var err error
	// AllowPaths are the only paths that are not denied.
	// IgnorePaths bypass all authorization checks.
	switch {
	case len(krbInfo.AllowPaths) > 0:
		pathAuthorizer, err = path.NewAllowedPathsAuthorizer(krbInfo.AllowPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create allow path authorizer: %w", err)
		}
	case len(krbInfo.IgnorePaths) > 0:
		pathAuthorizer, err = path.NewPassthroughAuthorizer(krbInfo.IgnorePaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create ignore path authorizer: %w", err)
		}
	}

	if pathAuthorizer != nil {
		return union.New(pathAuthorizer, authz), nil
	}

	return authz, nil
}

