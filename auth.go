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

package main

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/golang/glog"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	clientset "k8s.io/client-go/kubernetes"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1beta1"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1beta1"
)

type X509Config struct {
	ClientCAFile string
}

type AuthnConfig struct {
	X509 *X509Config
}

type AuthzConfig struct {
	ResourceAttributes *ResourceAttributes
}

type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

type AuthConfig struct {
	Authentication *AuthnConfig
	Authorization  *AuthzConfig
}

// kubeRBACProxyAuth implements AuthInterface
type kubeRBACProxyAuth struct {
	// authenticator identifies the user for requests to kube-rbac-proxy
	authenticator.Request
	// authorizerAttributeGetter builds authorization.Attributes for a request to kube-rbac-proxy
	authorizer.RequestAttributesGetter
	// authorizer determines whether a given authorization.Attributes is allowed
	authorizer.Authorizer
}

func newKubeRBACProxyAuth(authenticator authenticator.Request, authorizer authorizer.Authorizer, authzConfig *AuthzConfig) AuthInterface {
	return &kubeRBACProxyAuth{authenticator, newKubeRBACProxyAuthorizerAttributesGetter(authzConfig), authorizer}
}

// BuildAuth creates an authenticator, an authorizer, and a matching authorizer attributes getter compatible with the kube-rbac-proxy
func BuildAuth(client clientset.Interface, config AuthConfig) (AuthInterface, error) {
	// Get clients, if provided
	var (
		tokenClient authenticationclient.TokenReviewInterface
		sarClient   authorizationclient.SubjectAccessReviewInterface
	)
	if client != nil && !reflect.ValueOf(client).IsNil() {
		tokenClient = client.AuthenticationV1beta1().TokenReviews()
		sarClient = client.AuthorizationV1beta1().SubjectAccessReviews()
	}

	authenticator, err := buildAuthn(tokenClient, config.Authentication)
	if err != nil {
		return nil, err
	}

	authorizer, err := buildAuthz(sarClient)
	if err != nil {
		return nil, err
	}

	return newKubeRBACProxyAuth(authenticator, authorizer, config.Authorization), nil
}

// buildAuthn creates an authenticator compatible with the kubelet's needs
func buildAuthn(client authenticationclient.TokenReviewInterface, authn *AuthnConfig) (authenticator.Request, error) {
	authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:    false, // always require authentication
		CacheTTL:     2 * time.Minute,
		ClientCAFile: authn.X509.ClientCAFile,
	}

	if client == nil {
		return nil, errors.New("no client provided, cannot use webhook authentication")
	}
	authenticatorConfig.TokenAccessReviewClient = client

	authenticator, _, err := authenticatorConfig.New()
	return authenticator, err
}

// buildAuthz creates an authorizer compatible with the kubelet's needs
func buildAuthz(client authorizationclient.SubjectAccessReviewInterface) (authorizer.Authorizer, error) {
	if client == nil {
		return nil, errors.New("no client provided, cannot use webhook authorization")
	}
	authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		AllowCacheTTL:             5 * time.Minute,
		DenyCacheTTL:              30 * time.Second,
	}
	return authorizerConfig.New()
}

func newKubeRBACProxyAuthorizerAttributesGetter(authzConfig *AuthzConfig) authorizer.RequestAttributesGetter {
	return krpAuthorizerAttributesGetter{authzConfig}
}

type krpAuthorizerAttributesGetter struct {
	authzConfig *AuthzConfig
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n krpAuthorizerAttributesGetter) GetRequestAttributes(u user.Info, r *http.Request) authorizer.Attributes {
	apiVerb := ""
	switch r.Method {
	case "POST":
		apiVerb = "create"
	case "GET":
		apiVerb = "get"
	case "PUT":
		apiVerb = "update"
	case "PATCH":
		apiVerb = "patch"
	case "DELETE":
		apiVerb = "delete"
	}

	requestPath := r.URL.Path
	// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
	attrs := authorizer.AttributesRecord{
		User:            u,
		Verb:            apiVerb,
		Namespace:       "",
		APIGroup:        "",
		APIVersion:      "",
		Resource:        "",
		Subresource:     "",
		Name:            "",
		ResourceRequest: false,
		Path:            requestPath,
	}

	if n.authzConfig.ResourceAttributes != nil {
		attrs = authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       n.authzConfig.ResourceAttributes.Namespace,
			APIGroup:        n.authzConfig.ResourceAttributes.APIGroup,
			APIVersion:      n.authzConfig.ResourceAttributes.APIVersion,
			Resource:        n.authzConfig.ResourceAttributes.Resource,
			Subresource:     n.authzConfig.ResourceAttributes.Subresource,
			Name:            n.authzConfig.ResourceAttributes.Name,
			ResourceRequest: true,
		}
	}

	glog.V(5).Infof("kube-rbac-proxy request attributes: attrs=%#v", attrs)

	return attrs
}

func AuthRequest(auth AuthInterface, w http.ResponseWriter, req *http.Request) bool {
	// Authenticate
	u, ok, err := auth.AuthenticateRequest(req)
	if err != nil {
		glog.Errorf("Unable to authenticate the request due to an error: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	// Get authorization attributes
	attrs := auth.GetRequestAttributes(u, req)

	// Authorize
	authorized, _, err := auth.Authorize(attrs)
	if err != nil {
		msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
		glog.Errorf(msg, err)
		http.Error(w, msg, http.StatusInternalServerError)
		return false
	}
	if !authorized {
		msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
		glog.V(2).Info(msg)
		http.Error(w, msg, http.StatusForbidden)
		return false
	}

	return true
}
