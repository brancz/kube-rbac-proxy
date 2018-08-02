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
	"github.com/hkwi/h2c"
	flag "github.com/spf13/pflag"
	"golang.org/x/net/http2"
	k8sapiflag "k8s.io/apiserver/pkg/util/flag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"

	"github.com/brancz/kube-rbac-proxy/auth"
)

type config struct {
	insecureListenAddress  string
	secureListenAddress    string
	upstream               string
	upstreamForceH2C       bool
	resourceAttributesFile string
	auth                   auth.AuthConfig
	tls                    tlsConfig
}

type tlsConfig struct {
	certFile     string
	keyFile      string
	minVersion   string
	cipherSuites []string
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
		auth: auth.AuthConfig{
			Authentication: &auth.AuthnConfig{
				X509:   &auth.X509Config{},
				Header: &auth.AuthnHeaderConfig{},
			},
			Authorization: &auth.AuthzConfig{},
		},
	}
	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Add glog flags
	flagset.AddGoFlagSet(stdflag.CommandLine)

	// kube-rbac-proxy flags
	flagset.StringVar(&cfg.insecureListenAddress, "insecure-listen-address", "", "The address the kube-rbac-proxy HTTP server should listen on.")
	flagset.StringVar(&cfg.secureListenAddress, "secure-listen-address", "", "The address the kube-rbac-proxy HTTPs server should listen on.")
	flagset.StringVar(&cfg.upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.BoolVar(&cfg.upstreamForceH2C, "upstream-force-h2c", false, "Force h2c to communiate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only")
	flagset.StringVar(&cfg.resourceAttributesFile, "resource-attributes-file", "", "File spec of attributes-record to use for SubjectAccessReview. If unspecified, requests will attempted to be verified through non-resource-url attributes in the SubjectAccessReview.")

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
	flagset.Parse(os.Args[1:])

	upstreamURL, err := url.Parse(cfg.upstream)
	if err != nil {
		glog.Fatalf("Failed to build parse upstream URL: %v", err)
	}

	kcfg, err := rest.InClusterConfig()
	if err != nil {
		glog.Fatalf("Failed to build Kubernetes rest-config: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		glog.Fatalf("Failed to instantiate Kubernetes client: %v", err)
	}

	if cfg.resourceAttributesFile != "" {
		b, err := ioutil.ReadFile(cfg.resourceAttributesFile)
		if err != nil {
			glog.Fatalf("Failed to read resource-attribute file: %v", err)
		}

		err = yaml.Unmarshal(b, &cfg.auth.Authorization.ResourceAttributes)
		if err != nil {
			glog.Fatalf("Failed to parse resource-attribute file content: %v", err)
		}
	}

	auth, err := auth.BuildAuthHandler(kubeClient, &cfg.auth)
	if err != nil {
		glog.Fatalf("Failed to create auth: %v", err)
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

	if cfg.secureListenAddress != "" {
		srv := &http.Server{Handler: mux}

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

			version, err := tlsVersion(cfg.tls.minVersion)
			if err != nil {
				glog.Fatalf("TLS version invalid: %v", err)
			}

			cipherSuiteIDs, err := k8sapiflag.TLSCipherSuites(cfg.tls.cipherSuites)
			if err != nil {
				glog.Fatalf("Failed to convert TLS cipher suite name to ID: %v", err)
			}
			srv.TLSConfig = &tls.Config{
				CipherSuites: cipherSuiteIDs,
				Certificates: []tls.Certificate{cert},
				MinVersion:   version,
				// To enable http/2
				// See net/http.Server.shouldConfigureHTTP2ForServe for more context
				NextProtos: []string{"h2"},
			}
		}

		l, err := net.Listen("tcp", cfg.secureListenAddress)
		if err != nil {
			glog.Fatalf("Failed to listen on secure address: %v", err)
		}
		glog.Infof("Listening securely on %v", cfg.secureListenAddress)
		go srv.ServeTLS(l, cfg.tls.certFile, cfg.tls.keyFile)
	}

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

		// Background:
		//
		// golang's http2 server doesn't support h2c
		// https://github.com/golang/go/issues/16696
		//
		//
		// Action:
		//
		// Use hkwi/h2c so that you can properly handle HTTP Upgrade requests over plain TCP,
		// which is one of consequences for a h2c support.
		//
		// See https://github.com/golang/go/issues/14141 for more context.
		//
		// Possible alternative:
		//
		// We could potentially use grpc-go server's HTTP handler support
		// which would handle HTTP UPGRADE from http1.1 to http/2, especially in case
		// what you wanted kube-rbac-proxy to authn/authz was gRPC over h2c calls.
		//
		// Note that golang's http server requires a client(including gRPC) to send HTTP Upgrade req to
		// property start http/2.
		//
		// but it isn't straight-forward to understand.
		// Also note that at time of writing this, grpc-go's server implementation still lacks
		// a h2c support for communication against the upstream.
		//
		// See belows for more information:
		// - https://github.com/grpc/grpc-go/pull/1406/files
		// - https://github.com/grpc/grpc-go/issues/549#issuecomment-191458335
		// - https://github.com/golang/go/issues/14141#issuecomment-176465220
		h2cHandler := &h2c.Server{Handler: mux}

		srv := &http.Server{Handler: h2cHandler}

		l, err := net.Listen("tcp", cfg.insecureListenAddress)
		if err != nil {
			glog.Fatalf("Failed to listen on insecure address: %v", err)
		}
		glog.Infof("Listening insecurely on %v", cfg.insecureListenAddress)
		go srv.Serve(l)
	}

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		glog.Info("Received SIGTERM, exiting gracefully...")
	}
}
