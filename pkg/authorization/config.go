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

package authorization

import (
	"errors"
	"time"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/options"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
)

// Config holds configuration enabling request authorization
type AuthzConfig struct {
	*rewrite.RewriteAttributesConfig `json:",inline"`
	Static                           []static.StaticAuthorizationConfig `json:"static,omitempty"`
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
