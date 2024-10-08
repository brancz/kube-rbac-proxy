package app

import (
	"bytes"
	"encoding/json"
)

// SanitizingFilter implements the LogFilter interface from klog with custom functions to detect and mask tokens.
type SanitizingFilter struct{}

// Filter is the filter function for non-formatting logging functions of klog.
func (sf *SanitizingFilter) Filter(args []interface{}) []interface{} {
	for i, v := range args {
		if strValue, ok := v.(string); ok {
			if containsTokenReview(strValue) {
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
			if containsTokenReview(strValue) {
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
			if containsTokenReview(strValue) {
				keysAndValues[i] = maskTokenInLog(strValue)
			}
		}
	}
	return msg, keysAndValues
}

func containsTokenReview(logStr string) bool {
	return bytes.Contains([]byte(logStr), []byte(`"kind":"TokenReview"`))
}

func maskTokenInLog(logStr string) string {
	var logMap map[string]interface{}
	if err := json.Unmarshal([]byte(logStr), &logMap); err != nil {
		return logStr
	}

	if spec, ok := logMap["spec"].(map[string]interface{}); ok {
		if _, ok := spec["token"]; ok {
			spec["token"] = "<masked>"
		}
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(logMap); err != nil {
		return logStr
	}
	return buf.String()
}
