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
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Suite struct {
	KubeClient kubernetes.Interface
}

func NewSuiteFromKubeconfig(path string) (*Suite, error) {
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Suite{KubeClient: client}, nil
}

type TestSuite func(t *testing.T)

type Scenario struct {
	KubeClient kubernetes.Interface

	Name        string
	Description string

	Given Setup
	When  Condition
	Then  Check
}

/*type ScenarioContext struct {
	Namespace string
	Finalizer []Finalizer
}*/

func NamespaceFromContext(ctx context.Context) string {
	return ctx.Value("namespace").(string)
}

func NamespaceIntoContext(ctx context.Context, namespace string) context.Context {
	return context.WithValue(ctx, "namespace", namespace)
}

func FinalizerFromContext(ctx context.Context) []Finalizer {
	return ctx.Value("finalizer").([]Finalizer)
}

func FinalizerIntoContext(ctx context.Context, finalizer []Finalizer) context.Context {
	return context.WithValue(ctx, "finalizer", finalizer)
}

/*func (ctx *ScenarioContext) AddFinalizer(f Finalizer) {
	ctx.Finalizer = append(ctx.Finalizer, f)
}*/

type RunOpts func(ctx context.Context) context.Context

func RandomNamespace(client kubernetes.Interface) RunOpts {
	return func(ctx context.Context) context.Context {
		ctx = NamespaceIntoContext(ctx, rand.String(8))
		var finalizers []Finalizer
		finalizers = append(finalizers, func() error {
			return DeleteNamespace(client, ctx)
		})

		ctx = FinalizerIntoContext(ctx, finalizers)

		/*ctx.Namespace = rand.String(8)

		ctx.AddFinalizer(func() error {
			return DeleteNamespace(client, ctx.Namespace)
		})*/

		/*if err := CreateNamespace(client, ctx.Namespace); err != nil {
			panic(err)
		}*/
		// TODO: change CreateNamespace function signature
		if err := CreateNamespace(client, ctx); err != nil {
			panic(err)
		}

		return ctx
	}
}

/*func Timeout(d time.Duration) RunOpts {
	return func(ctx *ScenarioContext) *ScenarioContext {
		// TODO
		return ctx
	}
}*/

func (s Scenario) Run(t *testing.T, opts ...RunOpts) bool {
	/*ctx := &ScenarioContext{
		Namespace: "default",
	}*/
	ctx := NamespaceIntoContext(context.Background(), "default")

	for _, o := range opts {
		o(ctx)
	}

	/*defer func(ctx *ScenarioContext) {
		for _, f := range ctx.Finalizer {
			if err := f(); err != nil {
				panic(err)
			}
		}
	}(ctx)*/

	defer func(ctx context.Context) {
		finalizers := FinalizerFromContext(ctx)
		for _, f := range finalizers {
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

		if s.Given != nil {
			if err := s.Then(ctx); err != nil {
				t.Errorf("checks failed: %v", err)
			}
		}
	})
}

type Setup func(ctx context.Context) error

func Setups(ss ...Setup) Setup {
	return func(ctx context.Context) error {
		for _, s := range ss {
			if err := s(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

type Condition func(ctx context.Context) error

func Conditions(cs ...Condition) Condition {
	return func(ctx context.Context) error {
		for _, c := range cs {
			if err := c(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

type Check func(ctx context.Context) error

func Checks(cs ...Check) Check {
	return func(ctx context.Context) error {
		for _, c := range cs {
			if err := c(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

type Finalizer func() error
