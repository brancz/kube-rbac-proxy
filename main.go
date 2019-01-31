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
	stdflag "flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/oklog/run"
	flag "github.com/spf13/pflag"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	k8sapiflag "k8s.io/apiserver/pkg/util/flag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
)

type config struct {
	insecureListenAddress string
	secureListenAddress   string
	upstream              string
	upstreamForceH2C      bool
	auth                  proxy.Config
	tls                   tlsConfig
	kubeconfigLocation    string
}

type tlsConfig struct {
	certFile     string
	keyFile      string
	minVersion   string
	cipherSuites []string
}

type configfile struct {
	AuthorizationConfig *authz.Config `json:"authorization,omitempty"`
}

var versions = map[string]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
}

func tlsVersion(versionName string) (uint16, error) {
	if version, ok := versions[versionName]; ok {
		return version, nil
	}
	return 0, fmt.Errorf("unknown tls version %q", versionName)
}

func main() {
	cfg := config{
		auth: proxy.Config{
			Authentication: &authn.AuthnConfig{
				X509:   &authn.X509Config{},
				Header: &authn.AuthnHeaderConfig{},
				OIDC:   &authn.OIDCConfig{},
			},
			Authorization: &authz.Config{},
		},
	}
	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	configFileName := ""

	// Add glog flags
	flagset.AddGoFlagSet(stdflag.CommandLine)

	// kube-rbac-proxy flags
	flagset.StringVar(&cfg.insecureListenAddress, "insecure-listen-address", "", "The address the kube-rbac-proxy HTTP server should listen on.")
	flagset.StringVar(&cfg.secureListenAddress, "secure-listen-address", "", "The address the kube-rbac-proxy HTTPs server should listen on.")
	flagset.StringVar(&cfg.upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.BoolVar(&cfg.upstreamForceH2C, "upstream-force-h2c", false, "Force h2c to communiate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only")
	flagset.StringVar(&configFileName, "config-file", "", "Configuration file to configure kube-rbac-proxy.")

	// TLS flags
	flagset.StringVar(&cfg.tls.certFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert)")
	flagset.StringVar(&cfg.tls.keyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	flagset.StringVar(&cfg.tls.minVersion, "tls-min-version", "VersionTLS12", "Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flagset.StringSliceVar(&cfg.tls.cipherSuites, "tls-cipher-suites", nil, "Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used")

	// Auth flags
	flagset.StringVar(&cfg.auth.Authentication.X509.ClientCAFile, "client-ca-file", "", "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.")
	flagset.BoolVar(&cfg.auth.Authentication.Header.Enabled, "auth-header-fields-enabled", false, "When set to true, kube-rbac-proxy adds auth-related fields to the headers of http requests sent to the upstream")
	flagset.StringVar(&cfg.auth.Authentication.Header.UserFieldName, "auth-header-user-field-name", "x-remote-user", "The name of the field inside a http(2) request header to tell the upstream server about the user's name")
	flagset.StringVar(&cfg.auth.Authentication.Header.GroupsFieldName, "auth-header-groups-field-name", "x-remote-groups", "The name of the field inside a http(2) request header to tell the upstream server about the user's groups")
	flagset.StringVar(&cfg.auth.Authentication.Header.GroupSeparator, "auth-header-groups-field-separator", "|", "The separator string used for concatenating multiple group names in a groups header field's value")

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

	flagset.Parse(os.Args[1:])
	kcfg := initKubeConfig(cfg.kubeconfigLocation)

	upstreamURL, err := url.Parse(cfg.upstream)
	if err != nil {
		glog.Fatalf("Failed to build parse upstream URL: %v", err)
	}

	if configFileName != "" {
		glog.Infof("Reading config file: %s", configFileName)
		b, err := ioutil.ReadFile(configFileName)
		if err != nil {
			glog.Fatalf("Failed to read resource-attribute file: %v", err)
		}

		configfile := configfile{}

		err = yaml.Unmarshal(b, &configfile)
		if err != nil {
			glog.Fatalf("Failed to parse config file content: %v", err)
		}

		cfg.auth.Authorization = configfile.AuthorizationConfig
	}

	kubeClient, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		glog.Fatalf("Failed to instantiate Kubernetes client: %v", err)
	}

	var authenticator authenticator.Request
	// If OIDC configuration provided, use oidc authenticator
	if cfg.auth.Authentication.OIDC.IssuerURL != "" {
		authenticator, err = authn.NewOIDCAuthenticator(cfg.auth.Authentication.OIDC)
		if err != nil {
			glog.Fatalf("Failed to instantiate OIDC authenticator: %v", err)
		}

	} else {
		//Use Delegating authenticator

		tokenClient := kubeClient.AuthenticationV1beta1().TokenReviews()
		authenticator, err = authn.NewDelegatingAuthenticator(tokenClient, cfg.auth.Authentication)
		if err != nil {
			glog.Fatalf("Failed to instantiate delegating authenticator: %v", err)
		}

	}

	sarClient := kubeClient.AuthorizationV1beta1().SubjectAccessReviews()
	authorizer, err := authz.NewAuthorizer(sarClient)

	if err != nil {
		glog.Fatalf("Failed to create authorizer: %v", err)
	}

	auth, err := proxy.New(kubeClient, cfg.auth, authorizer, authenticator)

	if err != nil {
		glog.Fatalf("Failed to create rbac-proxy: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ok := auth.Handle(w, req)
		if !ok {
			return
		}

		proxy.ServeHTTP(w, req)
	}))

	var gr run.Group
	{
		if cfg.secureListenAddress != "" {
			srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{}}

			if cfg.tls.certFile == "" && cfg.tls.keyFile == "" {
				glog.Info("Generating self signed cert as no cert is provided")
				certBytes, keyBytes, err := certutil.GenerateSelfSignedCertKey("", nil, nil)
				if err != nil {
					glog.Fatalf("Failed to generate self signed cert and key: %v", err)
				}
				cert, err := tls.X509KeyPair(certBytes, keyBytes)
				if err != nil {
					glog.Fatalf("Failed to load generated self signed cert and key: %v", err)
				}

				srv.TLSConfig.Certificates = []tls.Certificate{cert}
			}

			version, err := tlsVersion(cfg.tls.minVersion)
			if err != nil {
				glog.Fatalf("TLS version invalid: %v", err)
			}

			cipherSuiteIDs, err := k8sapiflag.TLSCipherSuites(cfg.tls.cipherSuites)
			if err != nil {
				glog.Fatalf("Failed to convert TLS cipher suite name to ID: %v", err)
			}

			srv.TLSConfig.CipherSuites = cipherSuiteIDs
			srv.TLSConfig.MinVersion = version

			if err := http2.ConfigureServer(srv, nil); err != nil {
				glog.Fatalf("failed to configure http2 server: %v", err)
			}

			glog.Infof("Starting TCP socket on %v", cfg.secureListenAddress)
			l, err := net.Listen("tcp", cfg.secureListenAddress)
			if err != nil {
				glog.Fatalf("failed to listen on secure address: %v", err)
			}

			gr.Add(func() error {
				glog.Infof("Listening securely on %v", cfg.secureListenAddress)
				return srv.ServeTLS(l, cfg.tls.certFile, cfg.tls.keyFile)
			}, func(err error) {
				if err := srv.Shutdown(context.Background()); err != nil {
					glog.Errorf("failed to gracefully shutdown server: %v", err)
				}
				if err := l.Close(); err != nil {
					glog.Errorf("failed to gracefully close secure listener: %v", err)
				}
			})
		}
	}
	{
		if cfg.insecureListenAddress != "" {
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

			srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}

			l, err := net.Listen("tcp", cfg.insecureListenAddress)
			if err != nil {
				glog.Fatalf("Failed to listen on insecure address: %v", err)
			}

			gr.Add(func() error {
				glog.Infof("Listening insecurely on %v", cfg.insecureListenAddress)
				return srv.Serve(l)
			}, func(err error) {
				if err := srv.Shutdown(context.Background()); err != nil {
					glog.Errorf("failed to gracefully shutdown server: %v", err)
				}
				if err := l.Close(); err != nil {
					glog.Errorf("failed to gracefully close listener: %v", err)
				}
			})
		}
	}
	{
		sig := make(chan os.Signal)
		gr.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			glog.Info("received interrupt, shutting down")
			return nil
		}, func(err error) {
			close(sig)
		})
	}

	if err := gr.Run(); err != nil {
		glog.Fatalf("failed to run groups: %v", err)
	}
}

// Returns intiliazed config, allows local usage (outside cluster) based on provided kubeconfig or in-cluter
func initKubeConfig(kcLocation string) *rest.Config {

	if kcLocation != "" {
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", kcLocation)
		if err != nil {
			glog.Fatal("unable to build rest config based on provided path to kubeconfig file")
		}
		return kubeConfig
	}

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		glog.Fatal("cannot find Service Account in pod to build in-cluster rest config")
	}

	return kubeConfig
}
