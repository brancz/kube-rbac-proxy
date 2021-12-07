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

package proxy

import (
	"time"

	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

type authResponseCache interface {
	Add(key string, value *authenticator.Response)
	Get(key string) (*authenticator.Response, bool)
	Remove(key string)
}

var (
	_ authResponseCache = &lruCache{}
	_ authResponseCache = &fakeCache{}
)

// lruCache is wrapper around kubernetes lru cache to make the ttl setting a property of the cache.
type lruCache struct {
	wrap *utilcache.LRUExpireCache
	ttl  time.Duration
}

func newLRUTokenCache(ttl time.Duration) *lruCache {
	return &lruCache{
		wrap: utilcache.NewLRUExpireCache(4096),
		ttl:  ttl,
	}
}

func (c *lruCache) Add(key string, value *authenticator.Response) { c.wrap.Add(key, value, c.ttl) }
func (c *lruCache) Remove(key string)                             { c.wrap.Remove(key) }
func (c *lruCache) Get(key string) (*authenticator.Response, bool) {
	obj, ok := c.wrap.Get(key)
	if obj == nil {
		return nil, ok
	}
	return obj.(*authenticator.Response), ok
}

// fakeCache is a dummy substitute to keep working with cache simple.
type fakeCache struct{}

func (*fakeCache) Add(_ string, _ *authenticator.Response)      {}
func (*fakeCache) Remove(_ string)                              {}
func (*fakeCache) Get(_ string) (*authenticator.Response, bool) { return nil, false }
