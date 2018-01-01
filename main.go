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
	stdflag "flag"
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
	flag "github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type config struct {
	insecureListenAddress  string
	secureListenAddress    string
	upstream               string
	resourceAttributesFile string
	auth                   AuthConfig
	tls                    tlsConfig
}

type tlsConfig struct {
	certFile string
	keyFile  string
}

type AuthInterface interface {
	authenticator.Request
	authorizer.RequestAttributesGetter
	authorizer.Authorizer
}

func main() {
	cfg := config{
		auth: AuthConfig{
			Authentication: &AuthnConfig{
				X509: &X509Config{},
			},
			Authorization: &AuthzConfig{},
		},
	}
	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Add glog flags
	flagset.AddGoFlagSet(stdflag.CommandLine)

	// kube-rbac-proxy flags
	flagset.StringVar(&cfg.insecureListenAddress, "insecure-listen-address", "", "The address the kube-rbac-proxy HTTP server should listen on.")
	flagset.StringVar(&cfg.secureListenAddress, "secure-listen-address", "", "The address the kube-rbac-proxy HTTPs server should listen on.")
	flagset.StringVar(&cfg.upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.StringVar(&cfg.resourceAttributesFile, "resource-attributes-file", "", "File spec of attributes-record to use for SubjectAccessReview. If unspecified, requests will attempted to be verified through non-resource-url attributes in the SubjectAccessReview.")

	// TLS flags
	flagset.StringVar(&cfg.tls.certFile, "tls-cert-file", "server.crt", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert)")
	flagset.StringVar(&cfg.tls.keyFile, "tls-private-key-file", "server.key", "File containing the default x509 private key matching --tls-cert-file.")

	// Auth flags
	flagset.StringVar(&cfg.auth.Authentication.X509.ClientCAFile, "client-ca-file", "", "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.")
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

	auth, err := BuildAuth(kubeClient, cfg.auth)
	if err != nil {
		glog.Fatalf("Failed to create auth: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ok := AuthRequest(auth, w, req)
		if !ok {
			return
		}

		proxy.ServeHTTP(w, req)
	}))

	srv := &http.Server{Handler: mux}

	if cfg.secureListenAddress != "" {
		l, err := net.Listen("tcp", cfg.secureListenAddress)
		if err != nil {
			glog.Fatalf("Failed listen on secure address: %v", err)
		}
		go srv.ServeTLS(l, cfg.tls.certFile, cfg.tls.keyFile)
	}

	if cfg.insecureListenAddress != "" {
		l, err := net.Listen("tcp", cfg.insecureListenAddress)
		if err != nil {
			glog.Fatalf("Failed listen on insecure address: %v", err)
		}
		go srv.Serve(l)
	}

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		glog.Info("Received SIGTERM, exiting gracefully...")
	}
}
