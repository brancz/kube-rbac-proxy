/*
Copyright 2022 the kube-rbac-proxy maintainers All rights reserved.

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
package filters

import (
	"net/http"
	"path"
)

func WithAllowPaths(allowPaths []string, handler http.HandlerFunc) http.HandlerFunc {
	if len(allowPaths) == 0 {
		return handler
	}

	return func(w http.ResponseWriter, req *http.Request) {
		for _, pathAllowed := range allowPaths {
			found, err := path.Match(pathAllowed, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}

			if found {
				handler.ServeHTTP(w, req)
				return
			}
		}

		http.NotFound(w, req)
	}
}
