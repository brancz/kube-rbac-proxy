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

package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/golang/glog"
)

// CertReloader is the struct that parses a certificate/key pair,
// providing a goroutine safe GetCertificate method to retrieve the parsed content.
//
// The GetCertificate signature is compatible with https://golang.org/pkg/crypto/tls/#Config.GetCertificate
// and can be used to hot-reload a certificate/key pair.
//
// For hot-reloading the Watch method must be started explicitly.
type CertReloader struct {
	certPath, keyPath string

	// contains the watch targets (keys)
	// and the watch locations (values)
	watchables map[string]string

	mu   sync.RWMutex // protects the fields below
	cert *tls.Certificate
}

func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	watchables := make(map[string]string)

	w, in, err := newWatchable(certPath)
	if err != nil {
		return nil, fmt.Errorf("error adding cert watchable: %v", err)
	}
	watchables[w] = in

	w, in, err = newWatchable(keyPath)
	if err != nil {
		return nil, fmt.Errorf("error adding key watchable: %v", err)
	}
	watchables[w] = in

	r := &CertReloader{
		certPath:   certPath,
		keyPath:    keyPath,
		watchables: watchables,
	}

	if err := r.reload(); err != nil {
		return nil, fmt.Errorf("error loading certificates: %v", err)
	}

	return r, nil
}

func newWatchable(target string) (watchable, in string, _ error) {
	// simple case: the target is a file.
	// in that case we watch for changes in its own directory.
	watchable = filepath.Clean(target)
	in, _ = filepath.Split(target)
	in = filepath.Clean(in)

	stat, err := os.Lstat(target)
	if err != nil {
		return "", "", fmt.Errorf("lstat on %q failed: %v", target, err)
	}

	// k8s case: the target is a symlink.
	// Here, we watch the intermediate symlink (named `..data`)
	// in the same directory as the target.
	if stat.Mode()&os.ModeSymlink != 0 {
		dest, err := os.Readlink(target)
		if err != nil {
			return "", "", fmt.Errorf("lstat on %q failed: %v", target, err)

		}

		watchable, _ = filepath.Split(dest)
		watchable = filepath.Clean(watchable)
	}

	return
}

// Watch watches the configured certificate and key path and blocks the current goroutine
// until the scenario context is done or an error occurred during reloading.
func (r *CertReloader) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating fsnotify watcher: %v", err)
	}

	for _, v := range r.watchables {
		glog.V(4).Infof("watching: %q", v)

		if err := watcher.Add(v); err != nil {
			return fmt.Errorf("error adding watchable: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case event := <-watcher.Events:
			glog.V(5).Infof("watcher event %v", event)

			if _, ok := r.watchables[filepath.Clean(event.Name)]; !ok {
				continue
			}

			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

		case err := <-watcher.Errors:
			glog.Errorf("watch failed: %v", err)
			continue
		}

		if err := r.reload(); err != nil {
			return fmt.Errorf("reloading failed: %v", err)
		}
	}
}

func (r *CertReloader) reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	glog.V(4).Info("reloading key ", r.keyPath, " certificate ", r.certPath)

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("error loading certificate: %v", err)
	}

	r.cert = &cert
	return nil
}

// GetCertificate returns the current valid certificate.
// The ClientHello message is ignored
// and is just there to be compatible with https://golang.org/pkg/crypto/tls/#Config.GetCertificate.
func (r *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.cert, nil
}
