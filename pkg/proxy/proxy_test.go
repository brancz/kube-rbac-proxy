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
