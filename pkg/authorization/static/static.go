/*
Copyright 2023 the kube-rbac-proxy maintainers. All rights reserved.

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

package static

import (
	"context"
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/utils/set"
)

// StaticAuthorizationConfig describes what is needed to specify a static
// authorization.
type StaticAuthorizationConfig struct {
	User            UserConfig
	Verb            string `json:"verb,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	APIGroup        string `json:"apiGroup,omitempty"`
	Resource        string `json:"resource,omitempty"`
	Subresource     string `json:"subresource,omitempty"`
	Name            string `json:"name,omitempty"`
	ResourceRequest bool   `json:"resourceRequest,omitempty"`
	Path            string `json:"path,omitempty"`
}

type UserConfig struct {
	Name     string   `json:"name,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	GroupSet set.Set[string]
}

type staticAuthorizer struct {
	config []StaticAuthorizationConfig
}

// NewStaticAuthorizer creates an authorizer for static SubjectAccessReviews
func NewStaticAuthorizer(config []StaticAuthorizationConfig) (*staticAuthorizer, error) {
	for c := range config {
		if config[c].User.Groups != nil {
			config[c].User.GroupSet = set.New(config[c].User.Groups...)
		}

		if config[c].ResourceRequest != (config[c].Path == "") {
			return nil, fmt.Errorf("invalid configuration: resource requests must not include a path: %v", config)
		}
	}
	return &staticAuthorizer{config}, nil
}

func (saConfig StaticAuthorizationConfig) Matches(a authorizer.Attributes) bool {
	isAllowed := func(staticConf string, requestVal string) bool {
		if staticConf == "" {
			return true
		}
		return staticConf == requestVal
	}
	isGroupAllowed := func(requestGroups []string) bool {
		if len(saConfig.User.GroupSet) == 0 {
			return true
		}
		for _, group := range requestGroups {
			if _, exists := saConfig.User.GroupSet[group]; exists {
				return true
			}
		}
		return false
	}

	userName := ""
	userGroups := []string{}
	if a.GetUser() != nil {
		userName = a.GetUser().GetName()
		userGroups = a.GetUser().GetGroups()
	}

	if (saConfig.User.Name == "" || isAllowed(saConfig.User.Name, userName)) &&
		isGroupAllowed(userGroups) &&
		isAllowed(saConfig.Verb, a.GetVerb()) &&
		isAllowed(saConfig.Namespace, a.GetNamespace()) &&
		isAllowed(saConfig.APIGroup, a.GetAPIGroup()) &&
		isAllowed(saConfig.Resource, a.GetResource()) &&
		isAllowed(saConfig.Subresource, a.GetSubresource()) &&
		isAllowed(saConfig.Name, a.GetName()) &&
		isAllowed(saConfig.Path, a.GetPath()) &&
		saConfig.ResourceRequest == a.IsResourceRequest() {
		return true
	}
	return false
}

func (sa staticAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	// compare a against the configured static auths
	for _, saConfig := range sa.config {
		if saConfig.Matches(a) {
			return authorizer.DecisionAllow, "found corresponding static auth config", nil
		}
	}

	return authorizer.DecisionNoOpinion, "", nil
}
