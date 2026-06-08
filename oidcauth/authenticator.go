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

package oidcauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
)

const (
	// AuthenticationSourceOIDC indicates that OIDC verification authenticated the request.
	AuthenticationSourceOIDC AuthenticationSource = "oidc"
	// AuthenticationSourceKubernetes indicates that Kubernetes TokenReview authenticated the request.
	AuthenticationSourceKubernetes AuthenticationSource = "kubernetes"
)

// AuthenticationSource identifies the authentication backend that accepted a token.
type AuthenticationSource string

// TokenAuthenticator authenticates bearer tokens and returns Kubernetes user info.
type TokenAuthenticator interface {
	// Authenticate validates a bearer token and returns a Kubernetes identity.
	Authenticate(ctx context.Context, rawToken string) (*AuthenticationResult, error)
}

// AuthenticationResult stores an authenticated Kubernetes identity and token metadata.
type AuthenticationResult struct {
	// User is the Kubernetes identity derived from the token.
	User user.Info
	// Token is populated when OIDC verification authenticated the request.
	Token *VerifiedToken
	// Source records which backend authenticated the request.
	Source AuthenticationSource
}

// Authenticator validates OIDC bearer tokens or falls back to Kubernetes TokenReview.
type Authenticator struct {
	// Config stores authentication settings.
	Config Config

	httpClient    *http.Client
	restConfig    *rest.Config
	tokenReviewer TokenReviewer

	// tokenReviewerOnce protects lazy TokenReviewer initialization.
	tokenReviewerOnce sync.Once
	tokenReviewerErr  error
	verifierMu        sync.Mutex
	verifier          *oidc.IDTokenVerifier
}

// AuthenticatorOption customizes an Authenticator.
type AuthenticatorOption func(*Authenticator)

// WithHTTPClient sets the HTTP client used for OIDC discovery and JWKS requests.
func WithHTTPClient(client *http.Client) AuthenticatorOption {
	return func(authenticator *Authenticator) {
		authenticator.httpClient = client
	}
}

// WithKubernetesRESTConfig sets the REST config used by TokenReview fallback.
func WithKubernetesRESTConfig(config *rest.Config) AuthenticatorOption {
	return func(authenticator *Authenticator) {
		authenticator.restConfig = config
	}
}

// WithTokenReviewer sets the TokenReview client used by Kubernetes fallback.
func WithTokenReviewer(reviewer TokenReviewer) AuthenticatorOption {
	return func(authenticator *Authenticator) {
		authenticator.tokenReviewer = reviewer
	}
}

// NewAuthenticator builds a token authenticator from config.
func NewAuthenticator(config Config, opts ...AuthenticatorOption) (*Authenticator, error) {
	config.ApplyDefaults()
	authenticator := &Authenticator{
		Config: config,
	}
	for _, opt := range opts {
		opt(authenticator)
	}
	if authenticator.httpClient == nil {
		client, err := config.HTTPClient()
		if err != nil {
			return nil, err
		}
		authenticator.httpClient = client
	}
	return authenticator, nil
}

// Authenticate validates a bearer token and returns a Kubernetes identity.
func (a *Authenticator) Authenticate(ctx context.Context, rawToken string) (*AuthenticationResult, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, apierrors.NewUnauthorized("a Bearer token must be provided")
	}

	if a.Config.IssuerURL != "" {
		return a.authenticateOIDC(ctx, rawToken)
	}
	if a.Config.KubernetesFallbackEnabled() {
		return a.authenticateKubernetes(ctx, rawToken)
	}
	return nil, fmt.Errorf("OIDC issuer is not configured and Kubernetes fallback is disabled")
}

// authenticateOIDC validates a token through OIDC discovery and JWKS verification.
func (a *Authenticator) authenticateOIDC(ctx context.Context, rawToken string) (*AuthenticationResult, error) {
	verifier, err := a.oidcVerifier(ctx)
	if err != nil {
		return nil, apierrors.NewServiceUnavailable(fmt.Sprintf("OIDC discovery failed: %v", err))
	}

	oidcCtx := oidc.ClientContext(ctx, a.httpClient)
	idToken, err := verifier.Verify(oidcCtx, rawToken)
	if err != nil {
		if strings.Contains(err.Error(), "fetching keys") {
			return nil, apierrors.NewServiceUnavailable(fmt.Sprintf("OIDC JWKS verification failed: %v", err))
		}
		return nil, apierrors.NewUnauthorized("OIDC token verification failed")
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, apierrors.NewUnauthorized("OIDC token claims could not be parsed")
	}

	verified := &VerifiedToken{
		Issuer:   idToken.Issuer,
		Subject:  idToken.Subject,
		Audience: append([]string{}, idToken.Audience...),
		Claims:   claims,
	}
	if err := ValidateVerifiedClaims(a.Config, verified); err != nil {
		return nil, err
	}

	identity, err := KubernetesIdentityFromClaims(a.Config, verified)
	if err != nil {
		return nil, err
	}
	return &AuthenticationResult{
		User:   identity,
		Token:  verified,
		Source: AuthenticationSourceOIDC,
	}, nil
}

// authenticateKubernetes validates a token through the current cluster TokenReview API.
func (a *Authenticator) authenticateKubernetes(ctx context.Context, rawToken string) (*AuthenticationResult, error) {
	reviewer, err := a.kubernetesTokenReviewer()
	if err != nil {
		return nil, err
	}

	status, err := reviewer.ReviewToken(ctx, rawToken, a.Config.KubernetesAudiences)
	if err != nil {
		return nil, err
	}
	if status == nil || !status.Authenticated {
		return nil, apierrors.NewUnauthorized("Kubernetes TokenReview did not authenticate the token")
	}

	return &AuthenticationResult{
		User: &user.DefaultInfo{
			Name:   status.User.Username,
			UID:    status.User.UID,
			Groups: append([]string{}, status.User.Groups...),
			Extra:  tokenReviewExtra(status.User.Extra),
		},
		Source: AuthenticationSourceKubernetes,
	}, nil
}

// oidcVerifier returns a cached verifier and initializes provider discovery on demand.
func (a *Authenticator) oidcVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	a.verifierMu.Lock()
	defer a.verifierMu.Unlock()

	if a.verifier != nil {
		return a.verifier, nil
	}

	oidcCtx := oidc.ClientContext(ctx, a.httpClient)
	provider, err := oidc.NewProvider(oidcCtx, a.Config.IssuerURL)
	if err != nil {
		return nil, err
	}
	a.verifier = provider.Verifier(&oidc.Config{
		// Signature, issuer, JWKS, and signing algorithm checks still run in go-oidc.
		// Audience and time claims are skipped here because ValidateVerifiedClaims
		// applies the package-level multi-audience and configurable clock-skew rules.
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true,
	})
	return a.verifier, nil
}

// kubernetesTokenReviewer returns the configured or lazily constructed TokenReview backend.
func (a *Authenticator) kubernetesTokenReviewer() (TokenReviewer, error) {
	a.tokenReviewerOnce.Do(func() {
		if a.tokenReviewer != nil {
			return
		}
		if a.restConfig == nil {
			a.tokenReviewerErr = fmt.Errorf("Kubernetes REST config is required for TokenReview fallback")
			return
		}
		reviewer, err := NewCurrentClusterTokenReviewer(a.restConfig)
		if err != nil {
			a.tokenReviewerErr = err
			return
		}
		a.tokenReviewer = reviewer
	})
	if a.tokenReviewerErr != nil {
		return nil, a.tokenReviewerErr
	}
	return a.tokenReviewer, nil
}
