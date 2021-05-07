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

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/google/go-cmp/cmp"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	testclient "k8s.io/client-go/kubernetes/fake"
)

func TestProxyWithOIDCSupport(t *testing.T) {
	kc := testclient.NewSimpleClientset()
	cfg := Config{
		Authentication: &authn.AuthnConfig{
			OIDC: &authn.OIDCConfig{},
			Header: &authn.AuthnHeaderConfig{
				Enabled:         true,
				UserFieldName:   "user",
				GroupsFieldName: "groups",
			},
			Token: &authn.TokenConfig{},
		},
		Authorization: &authz.Config{},
	}

	fakeUser := user.DefaultInfo{Name: "Foo Bar", Groups: []string{"foo-bars"}}
	authenticator := fakeOIDCAuthenticator(t, &fakeUser)

	scenario := setupTestScenario()
	for _, v := range scenario {

		t.Run(v.description, func(t *testing.T) {

			w := httptest.NewRecorder()
			proxy, err := New(kc, cfg, v.authorizer, authenticator)

			if err != nil {
				t.Fatalf("Failed to instantiate test proxy. Details : %s", err.Error())
			}
			proxy.Handle(w, v.req)

			resp := w.Result()

			if resp.StatusCode != v.status {
				t.Errorf("Expected response: %d received : %d", v.status, resp.StatusCode)
			}

			if v.verifyUser {
				user := v.req.Header.Get(cfg.Authentication.Header.UserFieldName)
				groups := v.req.Header.Get(cfg.Authentication.Header.GroupsFieldName)
				if user != fakeUser.GetName() {
					t.Errorf("User in the response header does not match authenticated user. Expected : %s, received : %s ", fakeUser.GetName(), user)
				}
				if groups != strings.Join(fakeUser.GetGroups(), cfg.Authentication.Header.GroupSeparator) {
					t.Errorf("Groupsr in the response header does not match authenticated user groups. Expected : %s, received : %s ", fakeUser.GetName(), groups)
				}
			}
		})
	}
}

func TestGeneratingAuthorizerAttributes(t *testing.T) {
	cases := []struct {
		desc     string
		authzCfg *authz.Config
		req      *http.Request
		expected []authorizer.Attributes
	}{
		{
			"without resource attributes and rewrites",
			&authz.Config{},
			createRequest(nil, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "",
					APIGroup:        "",
					APIVersion:      "",
					Resource:        "",
					Subresource:     "",
					Name:            "",
					ResourceRequest: false,
					Path:            "/accounts",
				},
			},
		},
		{
			"without rewrites config",
			&authz.Config{ResourceAttributes: &authz.ResourceAttributes{Namespace: "tenant1", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"}},
			createRequest(nil, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
		{
			"with query param rewrites config",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(map[string]string{"namespace": "tenant1"}, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
		{
			"with query param rewrites config but missing URL query",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, nil),
			nil,
		},
		{
			"with http header rewrites config",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByHTTPHeader: &authz.HTTPHeaderRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, map[string]string{"namespace": "tenant1"}),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
		{
			"with http header rewrites config but missing header",
			&authz.Config{
				Rewrites:           &authz.SubjectAccessReviewRewrites{ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, nil),
			nil,
		},
		{
			"with http header and query param rewrites config",
			&authz.Config{
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByHTTPHeader:     &authz.HTTPHeaderRewriteConfig{Name: "namespace"},
					ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &authz.ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(map[string]string{"namespace": "tenant1"}, map[string]string{"namespace": "tenant2"}),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant2",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			t.Log(c.req.URL.Query())
			n := krpAuthorizerAttributesGetter{authzConfig: c.authzCfg}
			res := n.GetRequestAttributes(nil, c.req)
			if !cmp.Equal(res, c.expected) {
				t.Errorf("Generated authorizer attributes are not correct. Expected %v, recieved %v", c.expected, res)
			}
		})
	}
}

func createRequest(queryParams, headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/accounts", nil)
	if queryParams != nil {
		q := r.URL.Query()
		for k, v := range queryParams {
			q.Add(k, v)
		}
		r.URL.RawQuery = q.Encode()
	}
	if headers != nil {
		for k, v := range headers {
			r.Header.Set(k, v)
		}
	}
	return r
}

func setupTestScenario() []testCase {
	testScenario := []testCase{
		{
			description: "Request with invalid Token should be authenticated and rejected with 401",
			given: given{
				req:        fakeJWTRequest("GET", "/accounts", "Bearer INVALID"),
				authorizer: denier{},
			},
			expected: expected{
				status: http.StatusUnauthorized,
			},
		},
		{
			description: "Request with valid token should return 403 due to lack of permissions",
			given: given{
				req:        fakeJWTRequest("GET", "/accounts", "Bearer VALID"),
				authorizer: denier{},
			},
			expected: expected{
				status: http.StatusForbidden,
			},
		},
		{
			description: "Request with valid token, should return 200 due to lack of permissions",
			given: given{
				req:        fakeJWTRequest("GET", "/accounts", "Bearer VALID"),
				authorizer: approver{},
			},
			expected: expected{
				status:     http.StatusOK,
				verifyUser: true,
			},
		},
	}
	return testScenario
}

func fakeJWTRequest(method, path, token string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Add("Authorization", token)

	return req
}

func fakeOIDCAuthenticator(t *testing.T, fakeUser *user.DefaultInfo) authenticator.Request {

	auth := bearertoken.New(authenticator.TokenFunc(func(ctx context.Context, token string) (*authenticator.Response, bool, error) {
		if token != "VALID" {
			return nil, false, nil
		}
		return &authenticator.Response{User: fakeUser}, true, nil
	}))
	return auth
}

type denier struct{}

func (d denier) Authorize(ctx context.Context, auth authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	return authorizer.DecisionDeny, "user not allowed", nil
}

type approver struct{}

func (a approver) Authorize(ctx context.Context, auth authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	return authorizer.DecisionAllow, "user allowed", nil
}

type given struct {
	req        *http.Request
	authorizer authorizer.Authorizer
}

type expected struct {
	status     int
	verifyUser bool
}

type testCase struct {
	given
	expected
	description string
}
