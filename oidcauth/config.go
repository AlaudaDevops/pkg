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

// Package oidcauth provides reusable OIDC authentication and Kubernetes authorization helpers.
package oidcauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// GlobalInfoConfigMapName is the default ACP global-info ConfigMap name.
	GlobalInfoConfigMapName = "global-info"
	// GlobalInfoConfigMapNamespace is the default ACP global-info ConfigMap namespace.
	GlobalInfoConfigMapNamespace = "kube-public"
	// GlobalInfoOIDCIssuerKey is the global-info key that stores the OIDC issuer URL.
	GlobalInfoOIDCIssuerKey = "oidcIssuer"
	// GlobalInfoOIDCClientIDKey is the global-info key that stores the OIDC client ID.
	GlobalInfoOIDCClientIDKey = "oidcClientID"
)

const (
	// KubernetesFallbackDefault keeps the default Kubernetes fallback behavior.
	KubernetesFallbackDefault KubernetesFallbackPolicy = ""
	// KubernetesFallbackEnabled enables current-cluster Kubernetes TokenReview fallback.
	KubernetesFallbackEnabled KubernetesFallbackPolicy = "enabled"
	// KubernetesFallbackDisabled disables current-cluster Kubernetes TokenReview fallback.
	KubernetesFallbackDisabled KubernetesFallbackPolicy = "disabled"
)

const (
	// defaultClockSkew is the default token time validation leeway.
	defaultClockSkew = 2 * time.Minute
	// defaultOIDCRequestTimeout is the default bound for OIDC discovery and JWKS requests.
	defaultOIDCRequestTimeout = 30 * time.Second
)

// KubernetesFallbackPolicy controls whether Kubernetes TokenReview fallback is used when OIDC is not configured.
type KubernetesFallbackPolicy string

// Config describes OIDC authentication and Kubernetes fallback behavior.
type Config struct {
	// IssuerURL is the trusted OIDC issuer URL.
	IssuerURL string
	// Audiences are accepted token audiences.
	Audiences []string
	// UsernameClaims are checked in order to build the Kubernetes user name.
	UsernameClaims []string
	// GroupsClaims are claim names mapped to Kubernetes groups.
	GroupsClaims []string
	// RolesClaims are role claim names explicitly mapped to Kubernetes groups.
	RolesClaims []string
	// UserPrefix is prepended to the mapped Kubernetes user name.
	UserPrefix string
	// GroupPrefix is prepended to every mapped Kubernetes group.
	GroupPrefix string
	// RequiredClaims are string claims that must match exactly.
	RequiredClaims map[string]string
	// RequireEmailVerified requires email_verified=true when the email claim is used as username.
	RequireEmailVerified bool
	// CAFile is an optional PEM CA file for OIDC discovery and JWKS requests.
	CAFile string
	// CAData is optional PEM CA data for OIDC discovery and JWKS requests.
	CAData []byte
	// OIDCRequestTimeout bounds OIDC discovery and JWKS HTTP requests.
	OIDCRequestTimeout time.Duration
	// ClockSkew is the allowed token time validation leeway.
	ClockSkew time.Duration
	// Now returns the current time for validation and tests.
	Now func() time.Time
	// KubernetesFallback controls TokenReview fallback when IssuerURL is empty.
	KubernetesFallback KubernetesFallbackPolicy
	// KubernetesAudiences are passed to TokenReview fallback.
	KubernetesAudiences []string
}

// ApplyDefaults fills unset configuration fields with secure compatibility defaults.
func (c *Config) ApplyDefaults() {
	if c.UsernameClaims == nil {
		c.UsernameClaims = []string{"preferred_username", "email"}
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = defaultClockSkew
	}
	if c.OIDCRequestTimeout <= 0 {
		c.OIDCRequestTimeout = defaultOIDCRequestTimeout
	}
}

// ApplyGlobalInfo fills empty OIDC fields from global-info defaults.
func (c *Config) ApplyGlobalInfo(info *GlobalInfoConfig) {
	if info == nil {
		return
	}
	if c.IssuerURL == "" {
		c.IssuerURL = info.IssuerURL
	}
	if len(c.Audiences) == 0 && info.ClientID != "" {
		c.Audiences = []string{info.ClientID}
	}
}

// KubernetesFallbackEnabled returns true when TokenReview fallback should be used.
func (c Config) KubernetesFallbackEnabled() bool {
	return c.KubernetesFallback != KubernetesFallbackDisabled
}

// GlobalInfoConfig stores OIDC defaults loaded from ACP global-info.
type GlobalInfoConfig struct {
	// IssuerURL is the OIDC issuer URL from global-info.
	IssuerURL string
	// ClientID is the OIDC client ID from global-info.
	ClientID string
}

// GlobalInfoLoader loads OIDC defaults from a Kubernetes ConfigMap.
type GlobalInfoLoader struct {
	// Reader reads ConfigMaps from the current cluster.
	Reader client.Reader
	// Name is the ConfigMap name.
	Name string
	// Namespace is the ConfigMap namespace.
	Namespace string
}

// Load reads global-info and returns nil when the ConfigMap does not exist.
func (l *GlobalInfoLoader) Load(ctx context.Context) (*GlobalInfoConfig, error) {
	if l.Reader == nil {
		return nil, fmt.Errorf("global-info reader is nil")
	}

	name := l.Name
	if name == "" {
		name = GlobalInfoConfigMapName
	}
	namespace := l.Namespace
	if namespace == "" {
		namespace = GlobalInfoConfigMapNamespace
	}

	cm := &corev1.ConfigMap{}
	if err := l.Reader.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get ConfigMap %s/%s: %w", namespace, name, err)
	}

	return &GlobalInfoConfig{
		IssuerURL: cm.Data[GlobalInfoOIDCIssuerKey],
		ClientID:  cm.Data[GlobalInfoOIDCClientIDKey],
	}, nil
}

// HTTPClient builds an HTTP client for OIDC discovery and JWKS requests.
func (c Config) HTTPClient() (*http.Client, error) {
	timeout := c.oidcRequestTimeout()
	if c.CAFile == "" && len(c.CAData) == 0 {
		return &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   timeout,
		}, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if c.CAFile != "" {
		data, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read OIDC CA file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(data); !ok {
			return nil, fmt.Errorf("failed to parse OIDC CA file")
		}
	}
	if len(c.CAData) > 0 {
		if ok := pool.AppendCertsFromPEM(c.CAData); !ok {
			return nil, fmt.Errorf("failed to parse OIDC CA data")
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: timeout,
	}, nil
}

// oidcRequestTimeout returns the configured OIDC request timeout or the package default.
func (c Config) oidcRequestTimeout() time.Duration {
	if c.OIDCRequestTimeout > 0 {
		return c.OIDCRequestTimeout
	}
	return defaultOIDCRequestTimeout
}
