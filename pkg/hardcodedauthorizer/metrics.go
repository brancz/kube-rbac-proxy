/*
Copyright 2021 Frederic Branczyk All rights reserved.

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

// this is copied from library-go to avoid a hard dependency
package hardcodedauthorizer

import (
	"context"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

type metricsAuthorizer struct{}

// GetUser() user.Info - checked
// GetVerb() string - checked
// IsReadOnly() bool - na
// GetNamespace() string - na
// GetResource() string - na
// GetSubresource() string - na
// GetName() string - na
// GetAPIGroup() string - na
// GetAPIVersion() string - na
// IsResourceRequest() bool - checked
// GetPath() string - checked
func (metricsAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	if a.GetUser() == nil {
		return authorizer.DecisionNoOpinion, "", nil
	}
	if a.GetUser().GetName() != "system:serviceaccount:openshift-monitoring:prometheus-k8s" {
		return authorizer.DecisionNoOpinion, "", nil
	}
	if !a.IsResourceRequest() &&
		a.GetVerb() == "get" &&
		a.GetPath() == "/metrics" {
		return authorizer.DecisionAllow, "requesting metrics is allowed", nil
	}

	return authorizer.DecisionNoOpinion, "", nil
}

// NewHardCodedMetricsAuthorizer returns a hardcoded authorizer for checking metrics.
func NewHardCodedMetricsAuthorizer() *metricsAuthorizer {
	return new(metricsAuthorizer)
}
