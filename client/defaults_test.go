/*
Copyright 2022 The AlaudaDevops Authors.

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

package client

import (
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestNewDefaultClientWithTimeOut(t *testing.T) {
	g := NewGomegaWithT(t)

	os.Setenv("HTTP_CLIENT_TIMEOUT", "20")
	client := NewHTTPClient()

	g.Expect(client.Timeout).To(Equal(20 * time.Second))
}

func TestNewDefaultClientWithDefaultTimeOut(t *testing.T) {
	g := NewGomegaWithT(t)

	os.Unsetenv("HTTP_CLIENT_TIMEOUT")
	client := NewHTTPClient()

	g.Expect(client.Timeout).To(Equal(30 * time.Second))
}

func TestHttpClientOptionFunc(t *testing.T) {
	g := NewGomegaWithT(t)
	option := InsecureSkipVerifyOption

	client := NewHTTPClient(option)

	g.Expect(client.Timeout).To(Equal(30 * time.Second))
	g.Expect(client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify).To(Equal(true))
}
