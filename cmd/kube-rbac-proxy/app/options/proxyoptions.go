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
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/ghodss/yaml"
	"github.com/spf13/pflag"

	serverconfig "k8s.io/apiserver/pkg/server"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/pkg/authn/identityheaders"
	authz "github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

const loopbackLookupTimeout = 5

// ProxyOptions are options specific to the kube-rbac-proxy
type ProxyOptions struct {
	Upstream         string
	UpstreamForceH2C bool

	UpstreamCAFile         string
	UpstreamClientCertFile string
	UpstreamClientKeyFile  string

	UpstreamHeader *identityheaders.AuthnHeaderConfig

	AuthzConfigFileName string
	AllowPaths          []string
	IgnorePaths         []string

	ProxyEndpointsPort int

	TokenAudiences []string

	DisableHTTP2Serving bool
}

func (o *ProxyOptions) AddFlags(flagset *pflag.FlagSet) {
	flagset.StringVar(&o.Upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.BoolVar(&o.UpstreamForceH2C, "upstream-force-h2c", false, "Force h2c to communicate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only")

	// upstream tls options
	flagset.StringVar(&o.UpstreamCAFile, "upstream-ca-file", "", "The CA the upstream uses for TLS connection. This is required when the upstream uses TLS and its own CA certificate")
	flagset.StringVar(&o.UpstreamClientCertFile, "upstream-client-cert-file", "", "If set, the client will be used to authenticate the proxy to upstream. Requires --upstream-client-key-file to be set, too.")
	flagset.StringVar(&o.UpstreamClientKeyFile, "upstream-client-key-file", "", "The key matching the certificate from --upstream-client-cert-file. If set, requires --upstream-client-cert-file to be set, too.")

	flagset.StringVar(&o.AuthzConfigFileName, "config-file", "", "Configuration file to configure static and rewrites authorization of the kube-rbac-proxy.")
	flagset.StringSliceVar(&o.AllowPaths, "allow-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the request doesn't match, kube-rbac-proxy responds with a 404 status code. If omitted, the incoming request path isn't checked. Cannot be used with --ignore-paths.")
	flagset.StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the requst matches, it will proxy the request without performing an authentication or authorization check. Cannot be used with --allow-paths.")

	// upstream header options
	flagset.StringVar(&o.UpstreamHeader.UserFieldName, "auth-header-user-field-name", "x-remote-user", "The name of the field inside a http(2) request header to tell the upstream server about the user's name")
	flagset.StringVar(&o.UpstreamHeader.GroupsFieldName, "auth-header-groups-field-name", "x-remote-groups", "The name of the field inside a http(2) request header to tell the upstream server about the user's groups")
	flagset.StringVar(&o.UpstreamHeader.GroupSeparator, "auth-header-groups-field-separator", "|", "The separator string used for concatenating multiple group names in a groups header field's value")

	flagset.StringSliceVar(&o.TokenAudiences, "auth-token-audiences", []string{}, "Comma-separated list of token audiences to accept. By default a token does not have to have any specific audience. It is recommended to set a specific audience.")

	// proxy endpoints flag
	flagset.IntVar(&o.ProxyEndpointsPort, "proxy-endpoints-port", 0, "The port to securely serve proxy-specific endpoints (such as '/healthz'). Uses the host from the '--secure-listen-address'.")

	// http2 serving flag, remove with k8s 1.31
	flagset.BoolVar(&o.DisableHTTP2Serving, "disable-http2-serving", o.DisableHTTP2Serving, "If true, HTTP2 serving will be disabled [default=false]")
}

func (o *ProxyOptions) Validate() []error {
	var errs []error

	if len(o.UpstreamHeader.GroupSeparator) > 0 && len(o.UpstreamHeader.GroupsFieldName) == 0 {
		errs = append(errs, fmt.Errorf("--auth-header-groups-field-name must be set along with --auth-header-groups-field-separator"))
	}

	if len(o.AllowPaths) > 0 && len(o.IgnorePaths) > 0 {
		errs = append(errs, fmt.Errorf("cannot use --allow-paths and --ignore-paths together"))
	}

	for _, pathAllowed := range o.AllowPaths {
		_, err := path.Match(pathAllowed, "")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to verify allow path: %s", pathAllowed))
		}
	}

	for _, pathIgnored := range o.IgnorePaths {
		_, err := path.Match(pathIgnored, "")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to verify ignored path: %s", pathIgnored))
		}
	}

	// Verify secure connection settings, if necessary.
	if err := validateSecureConnectionConfig(o); err != nil {
		errs = append(errs, err)
	}

	return errs
}

func (o *ProxyOptions) ApplyTo(krpInfo *server.KubeRBACProxyInfo, authInfo *serverconfig.AuthenticationInfo, serving *serverconfig.SecureServingInfo) error {
	var err error

	krpInfo.UpstreamURL, err = url.Parse(o.Upstream)
	if err != nil {
		return fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	if err := krpInfo.SetUpstreamTransport(o.UpstreamCAFile, o.UpstreamClientCertFile, o.UpstreamClientKeyFile); err != nil {
		return fmt.Errorf("failed to setup transport for upstream: %w", err)
	}

	if configFileName := o.AuthzConfigFileName; len(configFileName) > 0 {
		krpInfo.Authorization, err = parseAuthorizationConfigFile(configFileName)
		if err != nil {
			return fmt.Errorf("failed to read the config file: %w", err)
		}
	}

	serving.DisableHTTP2 = o.DisableHTTP2Serving
	krpInfo.UpstreamHeaders = o.UpstreamHeader
	krpInfo.IgnorePaths = o.IgnorePaths
	krpInfo.AllowPaths = o.AllowPaths
	authInfo.APIAudiences = o.TokenAudiences

	return nil
}

func validateSecureConnectionConfig(o *ProxyOptions) error {
	if !identityheaders.HasIdentityHeadersEnabled(o.UpstreamHeader) && !o.UpstreamForceH2C {
		return nil
	}

	errLoopback := validateLoopbackAddress(o.Upstream)
	if errLoopback == nil {
		return nil
	}
	if o.UpstreamForceH2C {
		return fmt.Errorf("loopback address is required for h2c: %w", errLoopback)
	}

	klog.V(4).Infof("Failed to validate loopback address: %v", errLoopback)

	u, err := url.Parse(o.Upstream)
	if err != nil {
		return fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	// If Identity Headers are configured and it is not a loopback address,
	// verify that mTLS is configured.
	if len(o.UpstreamClientCertFile) == 0 || len(o.UpstreamClientKeyFile) == 0 || u.Scheme != "https" {
		return fmt.Errorf(
			"loopback address (currently configured: %q) or client cert/key are required for identity headers",
			o.Upstream,
		)
	}

	return nil
}

func validateLoopbackAddress(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(loopbackLookupTimeout)*time.Second)
	defer cancel()

	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	ip := net.ParseIP(u.Hostname())
	if ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("not a loopback address: %s", ip.String())
		}

		return nil
	}

	ips, err := (&net.Resolver{}).LookupIPAddr(ctx, u.Hostname())
	if err != nil {
		return fmt.Errorf("failed to lookup ip: %w", err)
	}

	for _, ip := range ips {
		if !ip.IP.IsLoopback() {
			return fmt.Errorf("not a loopback address: %s", ip.IP.String())
		}
	}

	return nil
}

type configfile struct {
	AuthorizationConfig *authz.AuthzConfig `json:"authorization,omitempty"`
}

func parseAuthorizationConfigFile(filePath string) (*authz.AuthzConfig, error) {
	klog.Infof("Reading config file: %s", filePath)
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource-attribute file: %w", err)
	}

	configFile := configfile{}

	if err := yaml.Unmarshal(b, &configFile); err != nil {
		return nil, fmt.Errorf("failed to parse config file content: %w", err)
	}

	// If RewriteAttributesConfig is not set, set it to an empty config.
	// This is to avoid nil plenty of pointer dereference checks further down.
	if configFile.AuthorizationConfig.RewriteAttributesConfig == nil {
		configFile.AuthorizationConfig.RewriteAttributesConfig = &rewrite.RewriteAttributesConfig{}
	}

	return configFile.AuthorizationConfig, nil
}
