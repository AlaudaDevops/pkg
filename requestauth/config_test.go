/*
Copyright 2026 The AlaudaDevops Authors.

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

package requestauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// failingGlobalInfoReader returns a configured error from Get.
type failingGlobalInfoReader struct {
	// err is returned from Get.
	err error
}

// Get returns the configured error.
func (r failingGlobalInfoReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return r.err
}

// List is unused and exists to satisfy client.Reader.
func (r failingGlobalInfoReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return nil
}

// TestConfigApplyGlobalInfo verifies global-info defaults only fill empty config fields.
func TestConfigApplyGlobalInfo(t *testing.T) {
	config := Config{
		PlatformURL: "https://configured-platform.example.com",
		Audiences:   []string{"configured-client"},
	}
	config.ApplyGlobalInfo(&GlobalInfoConfig{
		PlatformURL: "https://platform.example.com",
		ClusterName: "business",
		IssuerURL:   "https://issuer.example.com",
		ClientID:    "global-client",
	})

	if config.PlatformURL != "https://configured-platform.example.com" {
		t.Fatalf("platform URL = %q, want configured value", config.PlatformURL)
	}
	if config.ClusterName != "business" {
		t.Fatalf("cluster name = %q, want business", config.ClusterName)
	}
	if config.IssuerURL != "https://issuer.example.com" {
		t.Fatalf("issuer URL = %q, want global issuer", config.IssuerURL)
	}
	if got := fmt.Sprintf("%v", config.Audiences); got != "[configured-client]" {
		t.Fatalf("audiences = %s, want configured audience", got)
	}

	var nilConfig Config
	nilConfig.ApplyGlobalInfo(nil)
	if nilConfig.PlatformURL != "" || nilConfig.ClusterName != "" || nilConfig.IssuerURL != "" || len(nilConfig.Audiences) != 0 {
		t.Fatalf("nil global-info changed config: %#v", nilConfig)
	}

	var emptyConfig Config
	emptyConfig.ApplyGlobalInfo(&GlobalInfoConfig{ClientID: "global-client"})
	if got := fmt.Sprintf("%v", emptyConfig.Audiences); got != "[global-client]" {
		t.Fatalf("audiences = %s, want global client", got)
	}
}

// TestConfigPlatformInsecureSkipTLSVerify verifies the platform TLS compatibility default.
func TestConfigPlatformInsecureSkipTLSVerify(t *testing.T) {
	if !(Config{}).platformInsecureSkipTLSVerify() {
		t.Fatalf("default platform TLS policy = false, want true")
	}

	enabled := true
	if !(Config{PlatformInsecureSkipTLSVerify: &enabled}).platformInsecureSkipTLSVerify() {
		t.Fatalf("explicit true platform TLS policy = false")
	}

	disabled := false
	if (Config{PlatformInsecureSkipTLSVerify: &disabled}).platformInsecureSkipTLSVerify() {
		t.Fatalf("explicit false platform TLS policy = true")
	}
}

// TestGlobalInfoLoaderLoad verifies global-info loading defaults and error handling.
func TestGlobalInfoLoaderLoad(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	configMap := &corev1.ConfigMap{}
	configMap.Name = GlobalInfoConfigMapName
	configMap.Namespace = GlobalInfoConfigMapNamespace
	configMap.Data = map[string]string{
		GlobalInfoPlatformURLKey:  "https://platform.example.com",
		GlobalInfoClusterNameKey:  "business",
		GlobalInfoOIDCIssuerKey:   "https://issuer.example.com",
		GlobalInfoOIDCClientIDKey: "global-client",
	}

	loader := &GlobalInfoLoader{
		Reader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(configMap).Build(),
	}
	info, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if info.PlatformURL != "https://platform.example.com" || info.ClusterName != "business" || info.IssuerURL != "https://issuer.example.com" || info.ClientID != "global-client" {
		t.Fatalf("global-info = %#v, want ConfigMap data", info)
	}

	missingInfo, err := (&GlobalInfoLoader{
		Reader: fake.NewClientBuilder().WithScheme(scheme).Build(),
	}).Load(context.Background())
	if err != nil {
		t.Fatalf("Load() missing ConfigMap error = %v", err)
	}
	if missingInfo != nil {
		t.Fatalf("missing global-info = %#v, want nil", missingInfo)
	}

	_, err = (&GlobalInfoLoader{}).Load(context.Background())
	if err == nil {
		t.Fatalf("Load() nil reader error = nil")
	}

	getErr := apierrors.NewForbidden(schema.GroupResource{Group: "", Resource: "configmaps"}, "global-info", fmt.Errorf("denied"))
	_, err = (&GlobalInfoLoader{Reader: failingGlobalInfoReader{err: getErr}}).Load(context.Background())
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("Load() error = %v, want wrapped forbidden", err)
	}
}

// TestGlobalInfoLoaderLoadUsesCustomName verifies non-default ConfigMap keys are used.
func TestGlobalInfoLoaderLoadUsesCustomName(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	configMap := &corev1.ConfigMap{}
	configMap.Name = "custom-global-info"
	configMap.Namespace = "custom-namespace"
	configMap.Data = map[string]string{
		GlobalInfoClusterNameKey: "custom-cluster",
	}

	info, err := (&GlobalInfoLoader{
		Reader:    fake.NewClientBuilder().WithScheme(scheme).WithObjects(configMap).Build(),
		Name:      "custom-global-info",
		Namespace: "custom-namespace",
	}).Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if info.ClusterName != "custom-cluster" {
		t.Fatalf("cluster name = %q, want custom-cluster", info.ClusterName)
	}

	missingInfo, err := (&GlobalInfoLoader{
		Reader:    fake.NewClientBuilder().WithScheme(scheme).Build(),
		Name:      "custom-global-info",
		Namespace: "custom-namespace",
	}).Load(context.Background())
	if err != nil {
		t.Fatalf("Load() custom missing error = %v", err)
	}
	if missingInfo != nil {
		t.Fatalf("custom missing global-info = %#v, want nil", missingInfo)
	}
}

// TestConfigHTTPClientWithCustomCAs verifies CAData and CAFile client construction.
func TestConfigHTTPClientWithCustomCAs(t *testing.T) {
	certPEM := newTestCertificatePEM(t)

	dataClient, err := Config{CAData: certPEM, OIDCRequestTimeout: 75 * time.Millisecond}.HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient() CAData error = %v", err)
	}
	assertTLSRootCAs(t, dataClient)
	if dataClient.Timeout != 75*time.Millisecond {
		t.Fatalf("CAData client timeout = %v, want 75ms", dataClient.Timeout)
	}

	caFile, err := os.CreateTemp(t.TempDir(), "ca-*.crt")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := caFile.Write(certPEM); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := caFile.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	fileClient, err := Config{CAFile: caFile.Name()}.HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient() CAFile error = %v", err)
	}
	assertTLSRootCAs(t, fileClient)
}

// TestConfigHTTPClientWithCustomCAPreservesDefaultTransport verifies proxy and default transport settings survive custom CAs.
func TestConfigHTTPClientWithCustomCAPreservesDefaultTransport(t *testing.T) {
	certPEM := newTestCertificatePEM(t)
	proxyURL, err := url.Parse("http://proxy.example.com:8080")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	originalTransport := http.DefaultTransport
	defaultTransport := &http.Transport{
		Proxy: func(_ *http.Request) (*url.URL, error) {
			return proxyURL, nil
		},
		ForceAttemptHTTP2: true,
		MaxIdleConns:      17,
	}
	http.DefaultTransport = defaultTransport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})

	client, err := Config{CAData: certPEM}.HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient() error = %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if transport == defaultTransport {
		t.Fatalf("custom CA client reused http.DefaultTransport directly")
	}
	gotProxy, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "issuer.example.com"}})
	if err != nil {
		t.Fatalf("transport proxy error = %v", err)
	}
	if gotProxy == nil || gotProxy.String() != proxyURL.String() {
		t.Fatalf("transport proxy = %v, want %s", gotProxy, proxyURL)
	}
	if !transport.ForceAttemptHTTP2 || transport.MaxIdleConns != defaultTransport.MaxIdleConns {
		t.Fatalf("default transport settings were not preserved")
	}
	if defaultTransport.TLSClientConfig != nil && defaultTransport.TLSClientConfig.RootCAs != nil {
		t.Fatalf("http.DefaultTransport RootCAs were mutated")
	}
	assertTLSRootCAs(t, client)
}

// TestConfigHTTPClientRejectsInvalidCAs verifies CA parse and read failures.
func TestConfigHTTPClientRejectsInvalidCAs(t *testing.T) {
	if _, err := (Config{CAData: []byte("invalid")}).HTTPClient(); err == nil {
		t.Fatalf("HTTPClient() invalid CAData error = nil")
	}

	badFile := types.NamespacedName{Namespace: t.TempDir(), Name: "missing.crt"}
	if _, err := (Config{CAFile: badFile.Namespace + "/" + badFile.Name}).HTTPClient(); err == nil {
		t.Fatalf("HTTPClient() missing CAFile error = nil")
	}

	invalidFile, err := os.CreateTemp(t.TempDir(), "invalid-ca-*.crt")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := invalidFile.WriteString("invalid"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := invalidFile.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := (Config{CAFile: invalidFile.Name()}).HTTPClient(); err == nil {
		t.Fatalf("HTTPClient() invalid CAFile error = nil")
	}
}

// assertTLSRootCAs verifies a client has TLS roots configured.
func assertTLSRootCAs(t *testing.T, client *http.Client) {
	t.Helper()

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatalf("TLS root CAs were not configured")
	}
}

// newTestCertificatePEM creates a self-signed CA certificate for HTTP client tests.
func newTestCertificatePEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
