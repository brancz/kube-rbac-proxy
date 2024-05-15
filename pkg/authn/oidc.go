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
	"net/http"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

type OIDCAuthenticator struct {
	dynamicClientCA      *dynamiccertificates.DynamicFileCAContent
	requestAuthenticator authenticator.Request
}

var (
	_ (authenticator.Request) = (*OIDCAuthenticator)(nil)
)

// NewOIDCAuthenticator returns OIDC authenticator
func NewOIDCAuthenticator(ctx context.Context, config *OIDCConfig) (*OIDCAuthenticator, error) {
	dyCA, err := dynamiccertificates.NewDynamicCAContentFromFile("oidc-ca", config.CAFile)
	if err != nil {
		return nil, err
	}

	tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
		JWTAuthenticator: apiserver.JWTAuthenticator{
			Issuer: apiserver.Issuer{
				URL:       config.IssuerURL,
				Audiences: []string{config.ClientID},
			},
			ClaimMappings: apiserver.ClaimMappings{
				Username: apiserver.PrefixedClaimOrExpression{
					Prefix: &config.UsernamePrefix,
					Claim:  config.UsernameClaim,
				},
				Groups: apiserver.PrefixedClaimOrExpression{
					Prefix: &config.GroupsPrefix,
					Claim:  config.GroupsClaim,
				},
			},
		},
		CAContentProvider:    dyCA,
		SupportedSigningAlgs: config.SupportedSigningAlgs,
	})
	if err != nil {
		return nil, err
	}

	return &OIDCAuthenticator{
		dynamicClientCA:      dyCA,
		requestAuthenticator: bearertoken.New(tokenAuthenticator),
	}, nil
}

func (o *OIDCAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return o.requestAuthenticator.AuthenticateRequest(req)
}

func (o *OIDCAuthenticator) Run(ctx context.Context) {
	if o.dynamicClientCA != nil {
		o.dynamicClientCA.Run(ctx, 1)
	}
}
