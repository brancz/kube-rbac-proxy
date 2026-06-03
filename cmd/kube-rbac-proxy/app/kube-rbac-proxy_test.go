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
	"testing"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
)

func TestShouldRunSecureServer(t *testing.T) {
	t.Run("generic secure serving does not require legacy secure listen address", func(t *testing.T) {
		base := options.NewProxyRunOptions()
		opts := &completedProxyRunOptions{
			ProxyRunOptions: &options.ProxyRunOptions{
				SecureServing: base.SecureServing,
				LegacyOptions: &options.LegacyOptions{},
			},
		}
		opts.SecureServing.BindPort = 8443

		if !shouldRunSecureServer(opts) {
			t.Fatal("expected secure serving to start when bind port is set")
		}
	})

	t.Run("disabled secure serving does not start", func(t *testing.T) {
		base := options.NewProxyRunOptions()
		opts := &completedProxyRunOptions{
			ProxyRunOptions: &options.ProxyRunOptions{
				SecureServing: base.SecureServing,
				LegacyOptions: &options.LegacyOptions{},
			},
		}
		opts.SecureServing.BindPort = 0

		if shouldRunSecureServer(opts) {
			t.Fatal("expected secure serving to remain disabled when bind port is zero")
		}
	})
}
