/*
Copyright 2022 the kube-rbac-proxy maintainers All rights reserved.

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
package filters

import (
	"context"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func NewAllowPathAuthorizer(allowPaths []string) authorizer.Authorizer {
	if len(allowPaths) == 0 {
		return authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
			return authorizer.DecisionNoOpinion, "", nil
		})
	}

	pathAuthorizer := NewPathAuthorizer(allowPaths)

	return authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		decision, reason, err := pathAuthorizer.Authorize(ctx, a)
		if err != nil {
			return decision, reason, err
		}

		switch decision {
		case authorizer.DecisionAllow:
			return authorizer.DecisionNoOpinion, "", nil
		case authorizer.DecisionNoOpinion:
			return authorizer.DecisionDeny, "", nil
		case authorizer.DecisionDeny:
			return decision, reason, err
		default:
			return authorizer.DecisionDeny, "", err
		}
	})
}

func NewPathAuthorizer(alwaysAllowPaths []string) authorizer.Authorizer {
	var patterns []string
	paths := sets.NewString() // faster than trying to match every pattern every time
	for _, p := range alwaysAllowPaths {
		p = strings.TrimPrefix(p, "/")
		if len(p) == 0 {
			// matches "/"
			paths.Insert(p)
			continue
		}
		if strings.ContainsRune(p, '*') {
			patterns = append(patterns, p)
		} else {
			paths.Insert(p)
		}
	}

	return authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		pth := strings.TrimPrefix(a.GetPath(), "/")
		if paths.Has(pth) {
			return authorizer.DecisionAllow, "", nil
		}

		for _, pattern := range patterns {
			if found, err := path.Match(pattern, pth); err != nil {
				return authorizer.DecisionNoOpinion, "Error", err
			} else if found {
				return authorizer.DecisionAllow, "", nil
			}
		}

		return authorizer.DecisionDeny, "", nil
	})
}
