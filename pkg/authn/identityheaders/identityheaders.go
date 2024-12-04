/*
Copyright 2023 the kube-rbac-proxy maintainers. All rights reserved.

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

package identityheaders

import (
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
	"strings"

	"net/http"
)

// AuthnHeaderConfig contains authentication header settings which enable more information about the user identity to be sent to the upstream
type AuthnHeaderConfig struct {
	// Corresponds to the name of the field inside a http(2) request header
	// to tell the upstream server about the user's name
	UserFieldName string
	// Corresponds to the name of the field inside a http(2) request header
	// to tell the upstream server about the user's groups
	GroupsFieldName string
	// The separator string used for concatenating multiple group names in a groups header field's value
	GroupSeparator string
}

// WithAuthHeaders adds identity information to the headers.
// Must not be used, if connection is not encrypted with TLS.
func WithAuthHeaders(handler http.Handler, cfg *AuthnHeaderConfig) http.Handler {
	if !HasIdentityHeadersEnabled(cfg) {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// We don't want the client to impersonate someone else.
		req.Header.Del(cfg.UserFieldName)
		req.Header.Del(cfg.GroupsFieldName)

		u, ok := request.UserFrom(req.Context())
		if ok {
			// Seemingly well-known headers to tell the upstream about user's identity
			// so that the upstream can achieve the original goal of delegating RBAC authn/authz to kube-rbac-proxy
			req.Header.Set(cfg.UserFieldName, u.GetName())

			if cfg.GroupSeparator == "" {
				// Add each group as a separate header entry
				for _, group := range u.GetGroups() {
					if strings.Contains(group, ",") {
						// Drop groups containing standard separator
						klog.Infof("Dropping group %q because it contains a standard separator", group)
						continue
					}
					req.Header.Add(cfg.GroupsFieldName, group)
				}
			} else {
				// If GroupSeparator is set, concatenate groups using the separator
				var validGroups []string
				for _, group := range u.GetGroups() {
					if strings.Contains(group, cfg.GroupSeparator) {
						// Drop groups containing the separator
						klog.Infof("Dropping group %q because it contains the group separator %q",
							group, cfg.GroupSeparator)
						continue
					}
					validGroups = append(validGroups, group)
				}
				req.Header.Set(cfg.GroupsFieldName, strings.Join(validGroups, cfg.GroupSeparator))
			}
		}

		handler.ServeHTTP(w, req)
	})
}

func HasIdentityHeadersEnabled(cfg *AuthnHeaderConfig) bool {
	return len(cfg.GroupsFieldName) > 0 || len(cfg.UserFieldName) > 0
}
