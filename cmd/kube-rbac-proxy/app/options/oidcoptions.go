/*
Copyright 2022 the kube-rbac-proxy maintainers. All rights reserved.

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

package options

import (
	"fmt"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"

	"github.com/brancz/kube-rbac-proxy/pkg/server"

	"github.com/spf13/pflag"
)

type OIDCOptions struct {
	oidc.Options

	CAFile string
}

func (o *OIDCOptions) AddFlags(flagset *pflag.FlagSet) {
	//Authn OIDC flags
	flagset.StringVar(&o.JWTAuthenticator.Issuer.URL, "oidc-issuer", "", "The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).")
	flagset.StringSliceVar(&o.JWTAuthenticator.Issuer.Audiences, "oidc-clientID", []string{}, "The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.")
	flagset.StringVar(&o.JWTAuthenticator.ClaimMappings.Username.Claim, "oidc-username-claim", "email", "Identifier of the user in JWT claim, by default set to 'email'")
	flagset.StringVar(&o.JWTAuthenticator.ClaimMappings.Groups.Claim, "oidc-groups-claim", "groups", "Identifier of groups in JWT claim, by default set to 'groups'")
	flagset.StringArrayVar(&o.SupportedSigningAlgs, "oidc-sign-alg", []string{"RS256"}, "Supported signing algorithms, default RS256")
	flagset.StringVar(&o.CAFile, "oidc-ca-file", "", "If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.")

	uprefix := flagset.String("oidc-username-prefix", "", "If provided, the username will be prefixed with this value to prevent conflicts with other authentication strategies.")
	if uprefix != nil {
		o.JWTAuthenticator.ClaimMappings.Username.Prefix = uprefix
	}

	gprefix := flagset.String("oidc-groups-prefix", "", "If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.")
	if gprefix != nil {
		o.JWTAuthenticator.ClaimMappings.Groups.Prefix = gprefix
	}

}

func (o *OIDCOptions) Validate() []error {
	var errs []error
	return errs
}

func (o *OIDCOptions) ApplyTo(c *server.KubeRBACProxyInfo) error {
	if o.JWTAuthenticator.Issuer.URL == "" {
		return nil
	}

	dyCA, err := dynamiccertificates.NewDynamicCAContentFromFile("oidc-ca", o.CAFile)

	if err != nil {
		return fmt.Errorf("failed to create dynamic CA content: %w", err)
	}

	o.CAContentProvider = dyCA
	c.OIDCDynamicCAContent = dyCA
	c.OIDC = &o.Options

	return nil
}
