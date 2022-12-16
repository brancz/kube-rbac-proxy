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

// AuthnHeaderConfig contains authentication header settings which enable more information about the user identity to be sent to the upstream
type AuthnHeaderConfig struct {
	// When set to true, kube-rbac-proxy adds auth-related fields to the headers of http requests sent to the upstream
	Enabled bool
	// Corresponds to the name of the field inside a http(2) request header
	// to tell the upstream server about the user's name
	UserFieldName string
	// Corresponds to the name of the field inside a http(2) request header
	// to tell the upstream server about the user's groups
	GroupsFieldName string
	// The separator string used for concatenating multiple group names in a groups header field's value
	GroupSeparator string
}

// AuthnConfig holds all configurations related to authentication options
type AuthnConfig struct {
	X509   *X509Config
	Header *AuthnHeaderConfig
	OIDC   *OIDCConfig
	Token  *TokenConfig
}

// X509Config holds public client certificate used for authentication requests if specified
type X509Config struct {
	ClientCAFile              string
	UpstreamClientCertificate string
	UpstreamClientKey         string
}

// TokenConfig holds configuration as to how token authentication is to be done
type TokenConfig struct {
	Audiences []string
}

// OIDCConfig represents configuration used for JWT request authentication
type OIDCConfig struct {
	IssuerURL            string
	ClientID             string
	CAFile               string
	UsernameClaim        string
	UsernamePrefix       string
	GroupsClaim          string
	GroupsPrefix         string
	SupportedSigningAlgs []string
}
