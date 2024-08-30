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

package authn

import (
	"context"
	"errors"
	"net/http"
	"time"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/pkg/server/options"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

type DelegatingAuthenticator struct {
	dynamicClientCA      *dynamiccertificates.DynamicFileCAContent
	requestAuthenticator authenticator.Request
}

var (
	_ (authenticator.Request) = (*DelegatingAuthenticator)(nil)
)

// NewDelegatingAuthenticator creates an authenticator compatible with the kubelet's needs
func NewDelegatingAuthenticator(client authenticationclient.AuthenticationV1Interface, authn *AuthnConfig) (*DelegatingAuthenticator, error) {
	if client == nil {
		return nil, errors.New("tokenAccessReview client not provided, cannot use webhook authentication")
	}

	var (
		p   *dynamiccertificates.DynamicFileCAContent
		err error
	)

	authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous: &apiserver.AnonymousAuthConfig{
			Enabled: false, // always require authentication
		},
		// Better defaults would be here: apiserver/pkg/server/options/authentication.go.
		CacheTTL:                2 * time.Minute,
		TokenAccessReviewClient: client,
		APIAudiences:            authenticator.Audiences(authn.Token.Audiences),
		WebhookRetryBackoff:     options.DefaultAuthWebhookRetryBackoff(),
	}

	if len(authn.X509.ClientCAFile) > 0 {
		p, err = dynamiccertificates.NewDynamicCAContentFromFile("client-ca", authn.X509.ClientCAFile)
		if err != nil {
			return nil, err
		}
		authenticatorConfig.ClientCertificateCAContentProvider = p
	}

	authenticator, _, err := authenticatorConfig.New()
	if err != nil {
		return nil, err
	}

	return &DelegatingAuthenticator{requestAuthenticator: authenticator, dynamicClientCA: p}, nil
}

func (a *DelegatingAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return a.requestAuthenticator.AuthenticateRequest(req)
}

func (a *DelegatingAuthenticator) Run(ctx context.Context) {
	if a.dynamicClientCA != nil {
		a.dynamicClientCA.Run(ctx, 1)
	}
}
