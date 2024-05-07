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

package options

import (
	"fmt"

	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

var disabledFlagsType = map[string]string{
	"logtostderr":       "bool",
	"add-dir-header":    "bool",
	"alsologtostderr":   "bool",
	"log-backtrace-at":  "string",
	"log-dir":           "string",
	"log-file":          "string",
	"log-file-max-size": "uint64",
	"one-output":        "bool",
	"skip-headers":      "bool",
	"skip-log-headers":  "bool",
	"stderrthreshold":   "string",
}

func (o *ProxyRunOptions) addDisabledFlags(flagset *pflag.FlagSet) {
	// disabled flags
	o.flagSet = flagset // reference used for validation

	for name, typeStr := range disabledFlagsType {
		switch typeStr {
		case "bool":
			_ = flagset.Bool(name, false, "[DISABLED]")
		case "string":
			_ = flagset.String(name, "", "[DISABLED]")
		case "uint64":
			_ = flagset.Uint64(name, 0, "[DISABLED]")
		default:
			panic(fmt.Sprintf("unknown type %q", typeStr))
		}

		if err := flagset.MarkHidden(name); err != nil {
			panic(err)
		}
	}
}

func (o *ProxyRunOptions) validateDisabledFlags() error {
	// Removed upstream flags shouldn't be use
	for disabledOpt := range disabledFlagsType {
		if flag := o.flagSet.Lookup(disabledOpt); flag.Changed {
			klog.Warningf(`
==== Removed Flag Warning ======================

%s is removed in the k8s upstream and has no effect any more.

===============================================
		`, disabledOpt)
		}
	}

	return nil
}
