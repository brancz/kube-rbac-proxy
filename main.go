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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghodss/yaml"
	"github.com/oklog/run"
	"github.com/spf13/pflag"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/apiserver/pkg/server"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
)

var serverShutdownTimeout = 60 * time.Second

type config struct {
	insecureListenAddress string
	secureListenAddress   string
	upstream              string
	upstreamForceH2C      bool
	upstreamCAFile        string
	auth                  proxy.Config
	tls                   tlsConfig
	kubeconfigLocation    string
	allowPaths            []string
	ignorePaths           []string
	configFileName        string
	ServingOptions        *genericapiserveroptions.SecureServingOptionsWithLoopback
	AuthenticationOptions *genericapiserveroptions.DelegatingAuthenticationOptions
}

func NewConfig() *config {
	cfg := &config{
		auth: proxy.Config{
			Authentication: &authn.AuthnConfig{
				Header: &authn.AuthnHeaderConfig{},
				OIDC:   &authn.OIDCConfig{},
				Token:  &authn.TokenConfig{},
			},
			Authorization: &authz.Config{},
		},
		ServingOptions:        genericapiserveroptions.NewSecureServingOptions().WithLoopback(),
		AuthenticationOptions: genericapiserveroptions.NewDelegatingAuthenticationOptions(),
	}
	cfg.AuthenticationOptions.DisableAnonymous = true
	return cfg
}

// tlsConfig is no longer used. TLS configuration is now managed by SecureServingOptions
// This is here to keep tls-reload-interval for backward compatibility
type tlsConfig struct {
	reloadInterval time.Duration
}

func (cfg *config) AddFlags(flagset *pflag.FlagSet) {
	if cfg.ServingOptions == nil || cfg.AuthenticationOptions == nil {
		return
	}

	// kube-rbac-proxy flags
	flagset.StringVar(&cfg.insecureListenAddress, "insecure-listen-address", "", "The address the kube-rbac-proxy HTTP server should listen on.")
	flagset.StringVar(&cfg.secureListenAddress, "secure-listen-address", "", "The address the kube-rbac-proxy HTTPs server should listen on.")
	flagset.StringVar(&cfg.upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.BoolVar(&cfg.upstreamForceH2C, "upstream-force-h2c", false, "Force h2c to communiate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only")
	flagset.StringVar(&cfg.upstreamCAFile, "upstream-ca-file", "", "The CA the upstream uses for TLS connection. This is required when the upstream uses TLS and its own CA certificate")
	flagset.StringVar(&cfg.configFileName, "config-file", "", "Configuration file to configure kube-rbac-proxy.")
	flagset.StringSliceVar(&cfg.allowPaths, "allow-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the request doesn't match, kube-rbac-proxy responds with a 404 status code. If omitted, the incoming request path isn't checked. Cannot be used with --ignore-paths.")
	flagset.StringSliceVar(&cfg.ignorePaths, "ignore-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the requst matches, it will proxy the request without performing an authentication or authorization check. Cannot be used with --allow-paths.")

	// TLS flags
	flagset.StringVar(&cfg.ServingOptions.ServerCert.CertKey.CertFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert)")
	flagset.StringVar(&cfg.ServingOptions.ServerCert.CertKey.KeyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	flagset.StringVar(&cfg.ServingOptions.MinTLSVersion, "tls-min-version", "VersionTLS12", "Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flagset.StringSliceVar(&cfg.ServingOptions.CipherSuites, "tls-cipher-suites", nil, "Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used")
	flagset.DurationVar(&cfg.tls.reloadInterval, "tls-reload-interval", time.Minute, "The interval at which to watch for TLS certificate changes, by default set to 1 minute.")

	// Auth flags
	flagset.StringVar(&cfg.AuthenticationOptions.ClientCert.ClientCA, "client-ca-file", "", "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.")
	flagset.BoolVar(&cfg.AuthenticationOptions.SkipInClusterLookup, "authentication-skip-lookup", true, ""+
		"If false, the authentication-kubeconfig will be used to lookup missing authentication "+
		"configuration from the cluster.")
	flagset.BoolVar(&cfg.auth.Authentication.Header.Enabled, "auth-header-fields-enabled", false, "When set to true, kube-rbac-proxy adds auth-related fields to the headers of http requests sent to the upstream")
	flagset.StringVar(&cfg.auth.Authentication.Header.UserFieldName, "auth-header-user-field-name", "x-remote-user", "The name of the field inside a http(2) request header to tell the upstream server about the user's name")
	flagset.StringVar(&cfg.auth.Authentication.Header.GroupsFieldName, "auth-header-groups-field-name", "x-remote-groups", "The name of the field inside a http(2) request header to tell the upstream server about the user's groups")
	flagset.StringVar(&cfg.auth.Authentication.Header.GroupSeparator, "auth-header-groups-field-separator", "|", "The separator string used for concatenating multiple group names in a groups header field's value")
	flagset.StringSliceVar(&cfg.auth.Authentication.Token.Audiences, "auth-token-audiences", []string{}, "Comma-separated list of token audiences to accept. By default a token does not have to have any specific audience. It is recommended to set a specific audience.")

	//Authn OIDC flags
	flagset.StringVar(&cfg.auth.Authentication.OIDC.IssuerURL, "oidc-issuer", "", "The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).")
	flagset.StringVar(&cfg.auth.Authentication.OIDC.ClientID, "oidc-clientID", "", "The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.")
	flagset.StringVar(&cfg.auth.Authentication.OIDC.GroupsClaim, "oidc-groups-claim", "groups", "Identifier of groups in JWT claim, by default set to 'groups'")
	flagset.StringVar(&cfg.auth.Authentication.OIDC.UsernameClaim, "oidc-username-claim", "email", "Identifier of the user in JWT claim, by default set to 'email'")
	flagset.StringVar(&cfg.auth.Authentication.OIDC.GroupsPrefix, "oidc-groups-prefix", "", "If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringArrayVar(&cfg.auth.Authentication.OIDC.SupportedSigningAlgs, "oidc-sign-alg", []string{"RS256"}, "Supported signing algorithms, default RS256")
	flagset.StringVar(&cfg.auth.Authentication.OIDC.CAFile, "oidc-ca-file", "", "If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.")

	//Kubeconfig flag
	flagset.StringVar(&cfg.kubeconfigLocation, "kubeconfig", "", "Path to a kubeconfig file, specifying how to connect to the API server. If unset, in-cluster configuration will be used")
}

type configfile struct {
	AuthorizationConfig *authz.Config `json:"authorization,omitempty"`
}

func (cfg *config) ApplyTo(secureServingInfo **server.SecureServingInfo,
	loopbackClientConfig **rest.Config, authenticationInfo *server.AuthenticationInfo) error {
	if cfg.configFileName != "" {
		klog.Infof("Reading config file: %s", cfg.configFileName)
		b, err := os.ReadFile(cfg.configFileName)
		if err != nil {
			return fmt.Errorf("failed to read resource-attribute file: %w", err)
		}

		configfile := configfile{}

		if err := yaml.Unmarshal(b, &configfile); err != nil {
			return fmt.Errorf("failed to parse config file content: %w", err)
		}

		cfg.auth.Authorization = configfile.AuthorizationConfig
	}

	if cfg.secureListenAddress != "" {
		host, portString, err := net.SplitHostPort(cfg.secureListenAddress)
		if err != nil {
			return fmt.Errorf("secureListenAddress is invalid: %w", err)
		}
		port, err := strconv.Atoi(portString)
		if err != nil {
			return fmt.Errorf("secureListenAddress port is invalid: %w", err)
		}
		if t := net.ParseIP(host); t == nil {
			return fmt.Errorf("secureListenAddress host is invalid: %w", err)
		}
		cfg.ServingOptions.BindAddress = net.ParseIP(host)
		cfg.ServingOptions.BindPort = port

	}

	if err := cfg.ServingOptions.ApplyTo(secureServingInfo, loopbackClientConfig); err != nil {
		klog.Fatalf("Failed to apply serving options: %w", err)
	}
	if err := cfg.AuthenticationOptions.ApplyTo(authenticationInfo, *secureServingInfo, nil); err != nil {
		klog.Fatalf("Failed to apply authentication options: %w", err)
	}
	return nil
}

func main() {
	cfg := NewConfig()

	// Add klog flags
	klogFlags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	klog.InitFlags(klogFlags)

	flagset := pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
	flagset.AddGoFlagSet(klogFlags)

	cfg.AddFlags(flagset)

	err := flagset.Parse(os.Args[1:])
	if err != nil {
		klog.Fatalf("Failed to parse CLI flags: %w", err)
	}
	kcfg := initKubeConfig(cfg.kubeconfigLocation)

	upstreamURL, err := url.Parse(cfg.upstream)
	if err != nil {
		klog.Fatalf("Failed to parse upstream URL: %w", err)
	}

	hasCerts := !(cfg.ServingOptions.ServerCert.CertKey.CertFile == "") && !(cfg.ServingOptions.ServerCert.CertKey.KeyFile == "")
	hasInsecureListenAddress := cfg.insecureListenAddress != ""
	if !hasCerts || hasInsecureListenAddress {
		klog.Warning(`
==== Deprecation Warning ======================

Insecure listen address will be removed.
Using --insecure-listen-address won't be possible!

The ability to run kube-rbac-proxy without TLS certificates will be removed.
Not using --tls-cert-file and --tls-private-key-file won't be possible!

For more information, please go to https://github.com/brancz/kube-rbac-proxy/issues/187

===============================================

		`)
	}
	if cfg.tls.reloadInterval != time.Minute {
		klog.Warning(`
==== Deprecation Warning ======================

Flag --tls-reload-interval will be removed from future releases. It is here for
backward compatibility. New tls reload mechanism takes care of this automatically.
As of now, k8s default configs are being used. 

===============================================
        `)
	}
	kubeClient, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		klog.Fatalf("Failed to instantiate Kubernetes client: %w", err)
	}

	var authenticator authenticator.Request
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		secureServingInfo *server.SecureServingInfo
		// loopbackClientConfig is a placeholder so that SecureServingOptionsWithLoopback.ApplyTo
		// will create self-signed certificate. This is needed in case no tls certificate is passed in.
		loopbackClientConfig *rest.Config
		authenticationInfo   server.AuthenticationInfo
	)
	if err = cfg.ApplyTo(&secureServingInfo, &loopbackClientConfig, &authenticationInfo); err != nil {
		klog.Fatalf("Failed to apply config: %w", err)
	}

	// If OIDC configuration provided, use oidc authenticator
	if cfg.auth.Authentication.OIDC.IssuerURL != "" {
		oidcAuthenticator, err := authn.NewOIDCAuthenticator(cfg.auth.Authentication.OIDC)
		if err != nil {
			klog.Fatalf("Failed to instantiate OIDC authenticator: %w", err)
		}

		go oidcAuthenticator.Run(ctx)
		authenticator = oidcAuthenticator
	} else {
		klog.Infof("Valid token audiences: %s", strings.Join(cfg.auth.Authentication.Token.Audiences, ", "))

		authenticator = authenticationInfo.Authenticator
	}

	sarClient := kubeClient.AuthorizationV1()
	sarAuthorizer, err := authz.NewSarAuthorizer(sarClient)

	if err != nil {
		klog.Fatalf("Failed to create sar authorizer: %w", err)
	}

	staticAuthorizer, err := authz.NewStaticAuthorizer(cfg.auth.Authorization.Static)
	if err != nil {
		klog.Fatalf("Failed to create static authorizer: %w", err)
	}

	authorizer := union.New(
		staticAuthorizer,
		sarAuthorizer,
	)

	auth := proxy.New(cfg.auth, authorizer, authenticator)

	upstreamTransport, err := initTransport(cfg.upstreamCAFile)
	if err != nil {
		klog.Fatalf("Failed to set up upstream TLS connection: %w", err)
	}

	if len(cfg.allowPaths) > 0 && len(cfg.ignorePaths) > 0 {
		klog.Fatal("Cannot use --allow-paths and --ignore-paths together.")
	}

	for _, pathAllowed := range cfg.allowPaths {
		_, err := path.Match(pathAllowed, "")
		if err != nil {
			klog.Fatalf("Failed to verify allow path: %s", pathAllowed)
		}
	}

	for _, pathIgnored := range cfg.ignorePaths {
		_, err := path.Match(pathIgnored, "")
		if err != nil {
			klog.Fatalf("Failed to verify ignored path: %s", pathIgnored)
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.Transport = upstreamTransport

	if cfg.upstreamForceH2C {
		// Force http/2 for connections to the upstream i.e. do not start with HTTP1.1 UPGRADE req to
		// initialize http/2 session.
		// See https://github.com/golang/go/issues/14141#issuecomment-219212895 for more context
		proxy.Transport = &http2.Transport{
			// Allow http schema. This doesn't automatically disable TLS
			AllowHTTP: true,
			// Do disable TLS.
			// In combination with the schema check above. We could enforce h2c against the upstream server
			DialTLS: func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(netw, addr)
			},
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		found := len(cfg.allowPaths) == 0
		for _, pathAllowed := range cfg.allowPaths {
			found, err = path.Match(pathAllowed, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}
			if found {
				break
			}
		}
		if !found {
			http.NotFound(w, req)
			return
		}

		ignorePathFound := false
		for _, pathIgnored := range cfg.ignorePaths {
			ignorePathFound, err = path.Match(pathIgnored, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}
			if ignorePathFound {
				break
			}
		}

		if !ignorePathFound {
			ok := auth.Handle(w, req)
			if !ok {
				return
			}
		}

		proxy.ServeHTTP(w, req)
	}))

	var gr run.Group
	{
		if cfg.secureListenAddress != "" {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			gr.Add(func() error {
				klog.Infof("Listening securely on %v", cfg.secureListenAddress)

				stoppedCh, listenerStoppedCh, err := secureServingInfo.Serve(mux, serverShutdownTimeout, ctx.Done())
				if err != nil {
					klog.Infof("Serve returns error: %w", err)
					return err
				}
				<-listenerStoppedCh
				<-stoppedCh

				return err

			}, func(err error) {
				cancel()
			})
		}
	}
	{
		if cfg.insecureListenAddress != "" {
			srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}

			l, err := net.Listen("tcp", cfg.insecureListenAddress)
			if err != nil {
				klog.Fatalf("Failed to listen on insecure address: %w", err)
			}

			gr.Add(func() error {
				klog.Infof("Listening insecurely on %v", cfg.insecureListenAddress)
				return srv.Serve(l)
			}, func(err error) {
				if err := srv.Shutdown(context.Background()); err != nil {
					klog.Errorf("failed to gracefully shutdown server: %w", err)
				}
				if err := l.Close(); err != nil {
					klog.Errorf("failed to gracefully close listener: %w", err)
				}
			})
		}
	}
	{
		sig := make(chan os.Signal, 1)
		gr.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			klog.Info("received interrupt, shutting down")
			return nil
		}, func(err error) {
			close(sig)
		})
	}

	if err := gr.Run(); err != nil {
		klog.Fatalf("failed to run groups: %w", err)
	}
}

// Returns intiliazed config, allows local usage (outside cluster) based on provided kubeconfig or in-cluter
func initKubeConfig(kcLocation string) *rest.Config {

	if kcLocation != "" {
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", kcLocation)
		if err != nil {
			klog.Fatalf("unable to build rest config based on provided path to kubeconfig file: %w", err)
		}
		return kubeConfig
	}

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatalf("cannot find Service Account in pod to build in-cluster rest config: %w", err)
	}

	return kubeConfig
}
