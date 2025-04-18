/*
Copyright 2023 The AlaudaDevops Authors.

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

package config

import (
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"
)

func TestNewConfigWatcher(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	w := NewConfigWatcher(func(config *Config) {
		g.Expect(config.Data).To(gomega.BeEmpty())
		time.Sleep(2 * time.Second)
	})

	now := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		for i := 0; i < 2; i++ {
			w.Watch(&Config{})
			wg.Done()
		}
	}()
	wg.Wait()
	g.Expect(time.Since(now)).To(gomega.BeNumerically(">", 2*time.Second))
}
