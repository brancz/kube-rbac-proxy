/*
Copyright 2017 Frederic Branczyk Authors.

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

package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/options"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// Config holds configuration enabling request authorization
type Config struct {
	Rewrites               *SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes     *ResourceAttributes          `json:"resourceAttributes,omitempty"`
	ResourceAttributesFile string                       `json:"-"`
	Static                 []StaticAuthorizationConfig  `json:"static,omitempty"`
}

// SubjectAccessReviewRewrites describes how SubjectAccessReview may be
// rewritten on a given request.
type SubjectAccessReviewRewrites struct {
	ByQueryParameter *QueryParameterRewriteConfig `json:"byQueryParameter,omitempty"`
	ByHTTPHeader     *HTTPHeaderRewriteConfig     `json:"byHttpHeader,omitempty"`
}

// QueryParameterRewriteConfig describes which HTTP URL query parameter is to
// be used to rewrite a SubjectAccessReview on a given request.
type QueryParameterRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// HTTPHeaderRewriteConfig describes which HTTP header is to
// be used to rewrite a SubjectAccessReview on a given request.
type HTTPHeaderRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// ResourceAttributes describes attributes available for resource request authorization
type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

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
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// NewSarAuthorizer creates an authorizer compatible with the kubelet's needs
func NewSarAuthorizer(client authorizationclient.AuthorizationV1Interface) (authorizer.Authorizer, error) {
	if client == nil {
		return nil, errors.New("no client provided, cannot use webhook authorization")
	}
	authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		// Defaults are most probably taken from: kubernetes/pkg/kubelet/apis/config/v1beta1/defaults.go
		// Defaults that are more reasonable: apiserver/pkg/server/options/authorization.go
		AllowCacheTTL:       5 * time.Minute,
		DenyCacheTTL:        30 * time.Second,
		WebhookRetryBackoff: options.DefaultAuthWebhookRetryBackoff(),
	}
	return authorizerConfig.New()
}

type staticAuthorizer struct {
	config []StaticAuthorizationConfig
}

func (saConfig StaticAuthorizationConfig) Matches(a authorizer.Attributes) bool {
	isAllowed := func(staticConf string, requestVal string) bool {
		if staticConf == "" {
			return true
		} else {
			return staticConf == requestVal
		}
	}

	userName := ""
	if a.GetUser() != nil {
		userName = a.GetUser().GetName()
	}

	if isAllowed(saConfig.User.Name, userName) &&
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

func NewStaticAuthorizer(config []StaticAuthorizationConfig) (*staticAuthorizer, error) {
	for _, c := range config {
		if c.ResourceRequest != (c.Path == "") {
			return nil, fmt.Errorf("invalid configuration: resource requests must not include a path: %v", config)
		}
	}
	return &staticAuthorizer{config}, nil
}
