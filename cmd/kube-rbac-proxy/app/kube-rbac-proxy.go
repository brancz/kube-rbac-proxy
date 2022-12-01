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

package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/client-go/rest"
	k8sapiflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/term"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/filters"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

func NewKubeRBACProxyCommand() *cobra.Command {
	o := options.NewProxyRunOptions()
	cmd := &cobra.Command{
		Use: "kube-rbac-proxy",
		Long: `The kube-rbac-proxy is a small HTTP proxy for a single upstream
that can perform RBAC authorization against the Kubernetes API using SubjectAccessReview.`,

		// stop printing usage when the command errors
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			// silence client-go warnings.
			// kube-apiserver loopback clients should not log self-issued warnings.
			rest.SetDefaultWarningHandler(rest.NoWarnings{})
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			fs := cmd.Flags()

			k8sapiflag.PrintFlags(fs)

			// convert previous version of options
			// FIXME: this may rewrite some of the above secure serving defaults, prevent that
			// in case legacy options were unset
			if err := o.LegacyOptions.ConvertIntoSecureServingOptions(o.SecureServing); err != nil {
				return err
			}

			// set default options
			completedOptions, err := Complete(o)
			if err != nil {
				return err
			}

			// validate options
			if errs := completedOptions.Validate(); len(errs) != 0 {
				return utilerrors.NewAggregate(errs)
			}

			return Run(completedOptions)
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	fs := cmd.Flags()
	namedFlagSets := o.Flags()
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	k8sapiflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)

	return cmd
}

type completedProxyRunOptions struct {
	*options.ProxyRunOptions
}

func (o *completedProxyRunOptions) Validate() []error {
	var errs []error
	errs = append(errs, o.SecureServing.Validate()...)
	errs = append(errs, o.ProxyOptions.Validate()...)
	errs = append(errs, o.LegacyOptions.Validate(o.SecureServing.ServerCert.CertKey.CertFile, o.SecureServing.ServerCert.CertKey.KeyFile)...)

	return errs
}

// Complete sets defaults for the ProxyRunOptions.
// Should be called after the flags are parsed.
func Complete(o *options.ProxyRunOptions) (*completedProxyRunOptions, error) {

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve hostname for self-signed cert: %w", err)
	}

	if err := o.SecureServing.MaybeDefaultWithSelfSignedCerts(hostname, nil, nil); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	if o.ProxyOptions.ProxyEndpointsPort != 0 {
		proxySecureServing := *o.SecureServing
		proxySecureServing.BindPort = o.ProxyOptions.ProxyEndpointsPort
		o.ProxySecureServing = &proxySecureServing
	}

	// TODO: completely rework according to https://github.com/kubernetes/kubernetes/blob/0e54bd294237e8fc3e0f60f3195353f7c25e8a4c/cmd/kube-apiserver/app/server.go#L532-L533
	completed := &completedProxyRunOptions{
		ProxyRunOptions: o,
	}

	return completed, nil
}

func Run(opts *completedProxyRunOptions) error {
	cfg, err := createKubeRBACProxyConfig(opts)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var authenticator authenticator.Request
	// If OIDC configuration provided, use oidc authenticator
	if cfg.KubeRBACProxyInfo.Auth.Authentication.OIDC.IssuerURL != "" {
		oidcAuthenticator, err := authn.NewOIDCAuthenticator(cfg.KubeRBACProxyInfo.Auth.Authentication.OIDC)
		if err != nil {
			return fmt.Errorf("failed to instantiate OIDC authenticator: %w", err)
		}

		go oidcAuthenticator.Run(ctx)
		authenticator = oidcAuthenticator
	} else {
		//Use Delegating authenticator
		klog.Infof("Valid token audiences: %s", strings.Join(cfg.KubeRBACProxyInfo.Auth.Authentication.Token.Audiences, ", "))

		tokenClient := cfg.KubeRBACProxyInfo.KubeClient.AuthenticationV1()
		delegatingAuthenticator, err := authn.NewDelegatingAuthenticator(tokenClient, cfg.KubeRBACProxyInfo.Auth.Authentication)
		if err != nil {
			return fmt.Errorf("failed to instantiate delegating authenticator: %w", err)
		}

		go delegatingAuthenticator.Run(ctx)
		authenticator = delegatingAuthenticator
	}

	sarClient := cfg.KubeRBACProxyInfo.KubeClient.AuthorizationV1()
	sarAuthorizer, err := authz.NewSarAuthorizer(sarClient)
	if err != nil {
		return fmt.Errorf("failed to create sar authorizer: %w", err)
	}

	staticAuthorizer, err := authz.NewStaticAuthorizer(cfg.KubeRBACProxyInfo.Auth.Authorization.Static)
	if err != nil {
		return fmt.Errorf("failed to create static authorizer: %w", err)
	}

	authorizer := union.New(
		staticAuthorizer,
		sarAuthorizer,
	)

	proxy := httputil.NewSingleHostReverseProxy(cfg.KubeRBACProxyInfo.UpstreamURL)
	proxy.Transport = cfg.KubeRBACProxyInfo.UpstreamTransport

	if cfg.KubeRBACProxyInfo.UpstreamForceH2C {
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

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ignorePathFound := false
		for _, pathIgnored := range cfg.KubeRBACProxyInfo.IgnorePaths {
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
			handlerFunc := proxy.ServeHTTP
			handlerFunc = filters.WithAuthHeaders(cfg.KubeRBACProxyInfo.Auth.Authentication.Header, handlerFunc)
			handlerFunc = filters.WithAuthorization(authorizer, cfg.KubeRBACProxyInfo.Auth.Authorization, handlerFunc)
			handlerFunc = filters.WithAuthentication(authenticator, cfg.KubeRBACProxyInfo.Auth.Authentication.Token.Audiences, handlerFunc)
			handlerFunc(w, req)

			return
		}

		proxy.ServeHTTP(w, req)
	})
	handler = filters.WithAllowPaths(cfg.KubeRBACProxyInfo.AllowPaths, handler)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	var gr run.Group
	{
		if len(opts.LegacyOptions.SecureListenAddress) > 0 {
			cfg.SecureServing.ClientCA, err = cfg.GetClientCAProvider()
			if err != nil {
				return err
			}

			serverStopCtx, serverCtxCancel := context.WithCancel(ctx)
			gr.Add(func() error {
				stoppedCh, listenerStoppedCh, err := cfg.SecureServing.Serve(mux, 10*time.Second, serverStopCtx.Done())
				if err != nil {
					serverCtxCancel()
					return err
				}

				<-listenerStoppedCh
				<-stoppedCh
				return err
			}, func(err error) {
				serverCtxCancel()
			})

			if cfg.KubeRBACProxyInfo.ProxyEndpointsSecureServing != nil {
				proxyEndpointsMux := http.NewServeMux()
				proxyEndpointsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

				cfg.KubeRBACProxyInfo.ProxyEndpointsSecureServing.ClientCA, err = cfg.GetClientCAProvider()
				if err != nil {
					return err
				}

				proxyServerStopCtx, proxyServerCtxCancel := context.WithCancel(ctx)
				gr.Add(func() error {
					proxyStoppedCh, proxyListenerStoppedCh, err := cfg.KubeRBACProxyInfo.ProxyEndpointsSecureServing.Serve(
						proxyEndpointsMux, 10*time.Second, proxyServerStopCtx.Done())
					if err != nil {
						proxyServerCtxCancel()
						return err
					}
					<-proxyListenerStoppedCh
					<-proxyStoppedCh
					return err
				}, func(err error) {
					proxyServerCtxCancel()
				})
			}
		}
	}
	{
		// FIXME: remove before first stable release
		if insecureListenAddress := cfg.KubeRBACProxyInfo.InsecureListenAddress; insecureListenAddress != "" {
			srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}

			l, err := net.Listen("tcp", insecureListenAddress)
			if err != nil {
				return fmt.Errorf("failed to listen on insecure address: %w", err)
			}

			gr.Add(func() error {
				klog.Infof("Listening insecurely on %v", insecureListenAddress)
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
		return fmt.Errorf("failed to run groups: %w", err)
	}

	return nil
}

func createKubeRBACProxyConfig(opts *completedProxyRunOptions) (*server.KubeRBACProxyConfig, error) {
	proxyConfig := server.NewConfig()
	if err := opts.SecureServing.ApplyTo(&proxyConfig.SecureServing); err != nil {
		return nil, err
	}

	if opts.ProxySecureServing != nil {
		if err := opts.ProxySecureServing.ApplyTo(&proxyConfig.KubeRBACProxyInfo.ProxyEndpointsSecureServing); err != nil {
			return nil, err
		}
	}

	if err := opts.ProxyOptions.ApplyTo(proxyConfig.KubeRBACProxyInfo); err != nil {
		return nil, err
	}

	if err := opts.LegacyOptions.ApplyTo(proxyConfig.KubeRBACProxyInfo); err != nil {
		return nil, err
	}

	return proxyConfig, nil
}
