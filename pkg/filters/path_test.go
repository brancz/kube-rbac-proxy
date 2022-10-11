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
package filters_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/filters"
)

func emptyHandler(w http.ResponseWriter, r *http.Request) {}

func TestAllowPath(t *testing.T) {
	validPath := "/allowed"

	for _, tt := range []struct {
		name   string
		paths  []string
		status int
	}{
		{
			name:   "should let request through if path allowed",
			paths:  []string{validPath},
			status: http.StatusOK,
		},
		{
			name:   "should not let request through if path not allowed",
			paths:  []string{"/denied"},
			status: http.StatusNotFound,
		},
		{
			name:   "should let request through if no path specified",
			paths:  []string{},
			status: http.StatusOK,
		},
		{
			name:   "should not let request through if path is non-sense",
			paths:  []string{"[]a]"},
			status: http.StatusInternalServerError,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, validPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			filters.WithAllowPaths(tt.paths, emptyHandler).ServeHTTP(rec, req)
			res := rec.Result()

			if res.StatusCode != tt.status {
				t.Errorf("want: %d\nhave: %d\n", tt.status, res.StatusCode)
			}
		})
	}
}
