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

package kubetest

import (
	"github.com/wiremock/go-wiremock"
	"k8s.io/client-go/tools/clientcmd"
	"testing"

	"k8s.io/client-go/kubernetes"
)

func NewClientFromKubeconfig(path string) (kubernetes.Interface, error) {
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

type TestSuite func(t *testing.T)

type Scenario struct {
	KubeClient kubernetes.Interface

	Name        string
	Description string

	Given Action
	When  Action
	Then  Action
}

func (s Scenario) Run(t *testing.T) bool {
	ctx := &ScenarioContext{
		Namespace: "default",
		stubs:     map[string]*wiremock.StubRule{},
	}

	defer func(ctx *ScenarioContext) {
		for _, f := range ctx.CleanUp {
			if err := f(); err != nil {
				panic(err)
			}
		}
	}(ctx)

	return t.Run(s.Name, func(t *testing.T) {
		if s.Given != nil {
			if err := s.Given(ctx); err != nil {
				t.Fatalf("failed to create given setup: %v", err)
			}
		}

		if s.When != nil {
			if err := s.When(ctx); err != nil {
				t.Errorf("failed to evaluate state: %v", err)
			}
		}

		if s.Then != nil {
			if err := s.Then(ctx); err != nil {
				t.Errorf("checks failed: %v", err)
			}
		}
	})
}

type ScenarioContext struct {
	Namespace string
	CleanUp   []CleanUp
	stubs     map[string]*wiremock.StubRule
}

func (ctx *ScenarioContext) AddCleanUp(f CleanUp) {
	ctx.CleanUp = append(ctx.CleanUp, f)
}

// AddStub adds a wiremock test stub to the test scenario context
func (ctx *ScenarioContext) AddStub(name string, stub *wiremock.StubRule) {
	ctx.stubs[name] = stub
}

// GetStub retrieves a wiremock test stub by the given name
func (ctx *ScenarioContext) GetStub(name string) (*wiremock.StubRule, bool) {
	stub, found := ctx.stubs[name]
	return stub, found
}

type CleanUp func() error

type Action func(ctx *ScenarioContext) error

func Actions(ss ...Action) Action {
	return func(ctx *ScenarioContext) error {
		for _, s := range ss {
			if err := s(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}
