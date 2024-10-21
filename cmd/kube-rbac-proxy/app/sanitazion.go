/*
Copyright 2024 the kube-rbac-proxy maintainers. All rights reserved.

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
	"bytes"
	"encoding/json"
	v1 "k8s.io/api/authentication/v1"
	"strings"
)

// SanitizingFilter implements the LogFilter interface from klog with custom functions to detect and mask tokens.
type SanitizingFilter struct{}

// Filter is the filter function for non-formatting logging functions of klog.
func (sf *SanitizingFilter) Filter(args []interface{}) []interface{} {
	for i, v := range args {
		if strValue, ok := v.(string); ok {
			if strings.Contains(strValue, `"kind":"TokenReview"`) {
				args[i] = maskTokenInLog(strValue)
			}
		}
	}
	return args
}

// FilterF is the filter function for formatting logging functions of klog.
func (sf *SanitizingFilter) FilterF(format string, args []interface{}) (string, []interface{}) {
	for i, v := range args {
		if strValue, ok := v.(string); ok {
			if strings.Contains(strValue, `"kind":"TokenReview"`) {
				args[i] = maskTokenInLog(strValue)
			}
		}
	}
	return format, args
}

// FilterS is the filter function for structured logging functions of klog.
func (sf *SanitizingFilter) FilterS(msg string, keysAndValues []interface{}) (string, []interface{}) {
	for i, v := range keysAndValues {
		if strValue, ok := v.(string); ok {
			if strings.Contains(strValue, `"kind":"TokenReview"`) {
				keysAndValues[i] = maskTokenInLog(strValue)
			}
		}
	}
	return msg, keysAndValues
}

func maskTokenInLog(logStr string) string {
	var tokenReview v1.TokenReview
	if err := json.Unmarshal([]byte(logStr), &tokenReview); err != nil {
		return "<log content masked due to unmarshal failure>"
	}

	if tokenReview.Spec.Token != "" {
		tokenReview.Spec.Token = "<masked>"
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(tokenReview); err != nil {
		return "<log content masked due to encoding failure>"
	}
	return buf.String()
}
