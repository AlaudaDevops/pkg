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
	"fmt"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// PlatformReviewer performs self authentication and authorization against the
// ACP platform-routed Kubernetes API.
//
// The reviewer always uses the original request Bearer token as the Kubernetes
// client credential. Authentication-only calls create SelfSubjectReview and
// authorization calls create SelfSubjectAccessReview, so the platform API
// evaluates the identity and permissions of the token subject itself. The
// component ServiceAccount running this package does not need create permission
// on these self-review resources for the platform backend, but the token user
// must be accepted by the platform API and be allowed to create self reviews.
type PlatformReviewer interface {
	// ReviewSelfSubject returns the platform API userInfo for the request token.
	ReviewSelfSubject(ctx context.Context, rawToken string) (*authnv1.SelfSubjectReviewStatus, error)
	// ReviewSelfSubjectAccess checks whether the request token can perform the requested action.
	ReviewSelfSubjectAccess(ctx context.Context, rawToken string, attrs *AccessAttributes) (*authv1.SubjectAccessReviewStatus, error)
}

// PlatformKubernetesReviewer creates platform-routed Kubernetes clients from a
// base REST config and the request Bearer token.
type PlatformKubernetesReviewer struct {
	// BaseConfig contributes transport settings such as QPS, proxy, and CA data.
	BaseConfig *rest.Config
	// PlatformURL is the ACP platform URL.
	PlatformURL string
	// ClusterName is the ACP cluster name appended under /kubernetes/.
	ClusterName string
	// InsecureSkipTLSVerify disables TLS verification for platform-routed requests.
	InsecureSkipTLSVerify bool
}

// NewPlatformKubernetesReviewer builds a reviewer for the configured platform API.
func NewPlatformKubernetesReviewer(config Config, baseConfig *rest.Config) (*PlatformKubernetesReviewer, error) {
	if !config.PlatformConfigured() {
		return nil, fmt.Errorf("platformURL and clusterName are required for platform authentication")
	}
	return &PlatformKubernetesReviewer{
		BaseConfig:            baseConfig,
		PlatformURL:           config.PlatformURL,
		ClusterName:           config.ClusterName,
		InsecureSkipTLSVerify: config.platformInsecureSkipTLSVerify(),
	}, nil
}

// ReviewSelfSubject authenticates the token by creating a platform SelfSubjectReview.
func (r *PlatformKubernetesReviewer) ReviewSelfSubject(ctx context.Context, rawToken string) (*authnv1.SelfSubjectReviewStatus, error) {
	clientset, err := r.clientsetForToken(rawToken)
	if err != nil {
		return nil, err
	}
	review, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create platform SelfSubjectReview: %w", err)
	}
	return &review.Status, nil
}

// ReviewSelfSubjectAccess authorizes the token by creating a platform SelfSubjectAccessReview.
func (r *PlatformKubernetesReviewer) ReviewSelfSubjectAccess(ctx context.Context, rawToken string, attrs *AccessAttributes) (*authv1.SubjectAccessReviewStatus, error) {
	if attrs == nil || (attrs.ResourceAttributes == nil && attrs.NonResourceAttributes == nil) {
		return nil, fmt.Errorf("SelfSubjectAccessReview attributes are nil")
	}

	clientset, err := r.clientsetForToken(rawToken)
	if err != nil {
		return nil, err
	}
	review := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes:    attrs.ResourceAttributes,
			NonResourceAttributes: attrs.NonResourceAttributes,
		},
	}
	review, err = clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create platform SelfSubjectAccessReview: %w", err)
	}
	return &review.Status, nil
}

// clientsetForToken creates a Kubernetes clientset that uses the request token.
func (r *PlatformKubernetesReviewer) clientsetForToken(rawToken string) (kubernetes.Interface, error) {
	config, err := r.restConfigForToken(rawToken)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform Kubernetes clientset: %w", err)
	}
	return clientset, nil
}

// restConfigForToken creates a platform REST config whose only credential is the request token.
func (r *PlatformKubernetesReviewer) restConfigForToken(rawToken string) (*rest.Config, error) {
	if r == nil {
		return nil, fmt.Errorf("platform reviewer is nil")
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, apierrors.NewUnauthorized("a Bearer token must be provided")
	}
	if r.PlatformURL == "" || r.ClusterName == "" {
		return nil, fmt.Errorf("platformURL and clusterName are required for platform authentication")
	}

	config := platformTransportConfig(r.BaseConfig)
	config.Host = fmt.Sprintf("%s/kubernetes/%s", strings.TrimRight(r.PlatformURL, "/"), r.ClusterName)
	config.BearerToken = rawToken
	config.TLSClientConfig.Insecure = r.InsecureSkipTLSVerify
	return config, nil
}

// platformTransportConfig copies non-identity settings from a base REST config.
func platformTransportConfig(base *rest.Config) *rest.Config {
	config := &rest.Config{}
	if base == nil {
		return config
	}

	config.APIPath = base.APIPath
	config.ContentConfig = base.ContentConfig
	config.TLSClientConfig = rest.TLSClientConfig{
		ServerName: base.TLSClientConfig.ServerName,
		CAFile:     base.TLSClientConfig.CAFile,
		CAData:     append([]byte{}, base.TLSClientConfig.CAData...),
		NextProtos: append([]string{}, base.TLSClientConfig.NextProtos...),
	}
	config.UserAgent = base.UserAgent
	config.DisableCompression = base.DisableCompression
	config.QPS = base.QPS
	config.Burst = base.Burst
	config.RateLimiter = base.RateLimiter
	config.WarningHandler = base.WarningHandler
	config.Timeout = base.Timeout
	config.Dial = base.Dial
	config.Proxy = base.Proxy
	return config
}
