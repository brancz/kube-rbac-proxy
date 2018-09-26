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
	"errors"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1beta1"
)

// NewDelegatingAuthenticator creates an authenticator compatible with the kubelet's needs
func NewDelegatingAuthenticator(client authenticationclient.TokenReviewInterface, authn *AuthnConfig) (authenticator.Request, error) {

	if client == nil {
		return nil, errors.New("tokenAccessReview client not provided, cannot use webhook authentication")
	}

	authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:               false, // always require authentication
		CacheTTL:                2 * time.Minute,
		ClientCAFile:            authn.X509.ClientCAFile,
		TokenAccessReviewClient: client,
	}

	authenticator, _, err := authenticatorConfig.New()
	return authenticator, err
}
