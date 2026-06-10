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

// Package requestauth provides reusable request authentication and Kubernetes
// authorization helpers.
//
// The package supports three ordered authentication and authorization backends:
//
//  1. ACP platform Kubernetes API, selected from platformURL and clusterName.
//     When platformURL and clusterName are configured directly or discovered
//     from kube-public/global-info, the package first talks to
//     {platformURL}/kubernetes/{clusterName} with the original request Bearer
//     token. Authentication-only filters create authentication.k8s.io/v1
//     SelfSubjectReview against that platform-routed Kubernetes API and use the
//     returned userInfo as the request identity. Authorization filters create
//     authorization.k8s.io/v1 SelfSubjectAccessReview against the same endpoint
//     and therefore ask the platform-routed API whether the token's own user can
//     perform the requested resource or non-resource action.
//
//     This backend does not require the calling component ServiceAccount to
//     create TokenReview, SubjectAccessReview, SelfSubjectReview, or
//     SelfSubjectAccessReview resources, because the request is sent as the
//     original user token. The token user must be accepted by the platform API,
//     and the platform API must allow self review APIs for that user. Standard
//     Kubernetes installations normally bind self review permissions through
//     built-in discovery/basic-user roles, but platform distributions can
//     customize that policy.
//
//  2. OIDC token verification, disabled by default. When explicitly enabled,
//     the package verifies the Bearer token with OIDC discovery and JWKS, checks
//     issuer, audience, time claims, and required claims, then maps configured
//     claims to a Kubernetes user.Info. In authorization filters the caller's
//     component ServiceAccount must create authorization.k8s.io/v1
//     SubjectAccessReview resources in the current cluster so that the mapped
//     user and groups can be checked by Kubernetes RBAC.
//
//  3. Current-cluster Kubernetes TokenReview fallback, enabled by default. The
//     package asks the current cluster to authenticate the original Bearer token
//     through authentication.k8s.io/v1 TokenReview. In authentication-only
//     filters the calling component ServiceAccount must be allowed to create
//     tokenreviews.authentication.k8s.io. In authorization filters it must also
//     be allowed to create subjectaccessreviews.authorization.k8s.io, because
//     the returned TokenReview user is authorized with a SubjectAccessReview.
//
// Backends are tried strictly in the order above. Authentication failures and
// unavailable backends are logged and the next enabled backend is attempted.
// The request is accepted as soon as one backend succeeds. In authorization
// filters, authorization errors after a backend authenticates the request are
// final and later backends are not attempted. If every enabled backend fails
// authentication, the package returns the collected failure to the caller
// without logging or returning the raw token.
package requestauth

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
	// GlobalInfoClusterNameKey is the global-info key that stores the ACP cluster name.
	GlobalInfoClusterNameKey = "clusterName"
	// GlobalInfoPlatformURLKey is the global-info key that stores the ACP platform URL.
	GlobalInfoPlatformURLKey = "platformURL"
	// GlobalInfoOIDCIssuerKey is the global-info key that stores the OIDC issuer URL.
	GlobalInfoOIDCIssuerKey = "oidcIssuer"
	// GlobalInfoOIDCClientIDKey is the global-info key that stores the OIDC client ID.
	GlobalInfoOIDCClientIDKey = "oidcClientID"
)

const (
	// PlatformAuthenticationDefault enables platform auth when platform URL and cluster name are available.
	PlatformAuthenticationDefault PlatformAuthenticationPolicy = ""
	// PlatformAuthenticationEnabled requires platform auth configuration and attempts it first.
	PlatformAuthenticationEnabled PlatformAuthenticationPolicy = "enabled"
	// PlatformAuthenticationDisabled disables platform auth even when global-info contains platform fields.
	PlatformAuthenticationDisabled PlatformAuthenticationPolicy = "disabled"
)

const (
	// OIDCAuthenticationDefault keeps OIDC authentication disabled unless explicitly enabled.
	OIDCAuthenticationDefault OIDCAuthenticationPolicy = ""
	// OIDCAuthenticationEnabled enables OIDC token verification as the second backend.
	OIDCAuthenticationEnabled OIDCAuthenticationPolicy = "enabled"
	// OIDCAuthenticationDisabled disables OIDC token verification.
	OIDCAuthenticationDisabled OIDCAuthenticationPolicy = "disabled"
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

// PlatformAuthenticationPolicy controls whether the platform URL backend is used.
type PlatformAuthenticationPolicy string

// OIDCAuthenticationPolicy controls whether OIDC token verification is used.
type OIDCAuthenticationPolicy string

// KubernetesFallbackPolicy controls whether current-cluster Kubernetes TokenReview fallback is used.
type KubernetesFallbackPolicy string

// Config describes request authentication and authorization backend behavior.
type Config struct {
	// PlatformURL is the ACP platform URL used to build platform Kubernetes API requests.
	PlatformURL string
	// ClusterName is the ACP cluster name appended to the platform Kubernetes API URL.
	ClusterName string
	// PlatformInsecureSkipTLSVerify controls TLS verification for platform Kubernetes API requests.
	//
	// Nil keeps the connectors-compatible default of true, because platform
	// proxy certificates in existing ACP deployments are not always anchored in
	// the current pod's system trust store.
	PlatformInsecureSkipTLSVerify *bool
	// PlatformAuthentication controls the platform SelfSubjectReview/SSAR backend.
	PlatformAuthentication PlatformAuthenticationPolicy
	// OIDCAuthentication controls the OIDC verifier backend. It is disabled by default.
	OIDCAuthentication OIDCAuthenticationPolicy
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
	// KubernetesFallback controls current-cluster TokenReview fallback.
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

// ApplyGlobalInfo fills empty platform and OIDC fields from global-info defaults.
func (c *Config) ApplyGlobalInfo(info *GlobalInfoConfig) {
	if info == nil {
		return
	}
	if c.PlatformURL == "" {
		c.PlatformURL = info.PlatformURL
	}
	if c.ClusterName == "" {
		c.ClusterName = info.ClusterName
	}
	if c.IssuerURL == "" {
		c.IssuerURL = info.IssuerURL
	}
	if len(c.Audiences) == 0 && info.ClientID != "" {
		c.Audiences = []string{info.ClientID}
	}
}

// PlatformAuthenticationEnabled returns true when the platform backend should be attempted.
func (c Config) PlatformAuthenticationEnabled() bool {
	if c.PlatformAuthentication == PlatformAuthenticationDisabled {
		return false
	}
	if c.PlatformAuthentication == PlatformAuthenticationEnabled {
		return true
	}
	return c.PlatformURL != "" && c.ClusterName != ""
}

// PlatformConfigured returns true when enough platform endpoint data is available.
func (c Config) PlatformConfigured() bool {
	return c.PlatformURL != "" && c.ClusterName != ""
}

// platformInsecureSkipTLSVerify returns the configured platform TLS policy.
func (c Config) platformInsecureSkipTLSVerify() bool {
	if c.PlatformInsecureSkipTLSVerify == nil {
		return true
	}
	return *c.PlatformInsecureSkipTLSVerify
}

// OIDCAuthenticationEnabled returns true when OIDC verification should be attempted.
func (c Config) OIDCAuthenticationEnabled() bool {
	return c.OIDCAuthentication == OIDCAuthenticationEnabled
}

// KubernetesFallbackEnabled returns true when TokenReview fallback should be used.
func (c Config) KubernetesFallbackEnabled() bool {
	return c.KubernetesFallback != KubernetesFallbackDisabled
}

// GlobalInfoConfig stores platform and OIDC defaults loaded from ACP global-info.
type GlobalInfoConfig struct {
	// PlatformURL is the ACP platform URL from global-info.
	PlatformURL string
	// ClusterName is the ACP cluster name from global-info.
	ClusterName string
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
		PlatformURL: cm.Data[GlobalInfoPlatformURLKey],
		ClusterName: cm.Data[GlobalInfoClusterNameKey],
		IssuerURL:   cm.Data[GlobalInfoOIDCIssuerKey],
		ClientID:    cm.Data[GlobalInfoOIDCClientIDKey],
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

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport is %T, want *http.Transport", http.DefaultTransport)
	}
	transport := defaultTransport.Clone()
	tlsConfig := &tls.Config{}
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
	}
	tlsConfig.RootCAs = pool
	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// oidcRequestTimeout returns the configured OIDC request timeout or the package default.
func (c Config) oidcRequestTimeout() time.Duration {
	if c.OIDCRequestTimeout > 0 {
		return c.OIDCRequestTimeout
	}
	return defaultOIDCRequestTimeout
}
