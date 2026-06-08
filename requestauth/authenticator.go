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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	authnv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"knative.dev/pkg/logging"
)

const (
	// AuthenticationSourcePlatform indicates that platform SelfSubjectReview authenticated the request.
	AuthenticationSourcePlatform AuthenticationSource = "platform"
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

// TokenAccessAuthenticator authenticates and authorizes bearer tokens for one access request.
type TokenAccessAuthenticator interface {
	// AuthenticateAndAuthorize validates the token and checks access attributes.
	AuthenticateAndAuthorize(ctx context.Context, rawToken string, attrs *AccessAttributes, reviewer SubjectAccessReviewer) (*AuthenticationResult, error)
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
	platform      PlatformReviewer

	// tokenReviewerOnce protects lazy TokenReviewer initialization.
	tokenReviewerOnce sync.Once
	tokenReviewerErr  error
	platformOnce      sync.Once
	platformErr       error
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

// WithPlatformReviewer sets the platform SelfSubjectReview/SSAR client used by the platform backend.
func WithPlatformReviewer(reviewer PlatformReviewer) AuthenticatorOption {
	return func(authenticator *Authenticator) {
		authenticator.platform = reviewer
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
	authenticator.httpClient = oidcHTTPClientWithTimeout(authenticator.httpClient, config.oidcRequestTimeout())
	return authenticator, nil
}

// oidcHTTPClientWithTimeout returns an HTTP client that has a timeout for OIDC upstream requests.
func oidcHTTPClientWithTimeout(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil || client.Timeout > 0 {
		return client
	}

	copied := *client
	copied.Timeout = timeout
	return &copied
}

// Authenticate validates a bearer token and returns a Kubernetes identity.
func (a *Authenticator) Authenticate(ctx context.Context, rawToken string) (*AuthenticationResult, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, apierrors.NewUnauthorized("a Bearer token must be provided")
	}

	failures := []backendFailure{}
	if a.Config.PlatformAuthenticationEnabled() {
		result, err := a.authenticatePlatform(ctx, rawToken)
		if err == nil {
			logging.FromContext(ctx).Infow("request authentication backend succeeded", "source", AuthenticationSourcePlatform, "user", result.User.GetName())
			return result, nil
		}
		logging.FromContext(ctx).Warnw("request authentication backend failed", "source", AuthenticationSourcePlatform, "error", err)
		failures = append(failures, backendFailure{source: AuthenticationSourcePlatform, err: err})
	} else {
		logging.FromContext(ctx).Debugw("request authentication backend skipped", "source", AuthenticationSourcePlatform, "reason", "disabled or missing platformURL/clusterName")
	}

	if a.Config.OIDCAuthenticationEnabled() {
		result, err := a.authenticateOIDC(ctx, rawToken)
		if err == nil {
			logging.FromContext(ctx).Infow("request authentication backend succeeded", "source", AuthenticationSourceOIDC, "user", result.User.GetName())
			return result, nil
		}
		logging.FromContext(ctx).Warnw("request authentication backend failed", "source", AuthenticationSourceOIDC, "error", err)
		failures = append(failures, backendFailure{source: AuthenticationSourceOIDC, err: err})
	} else {
		logging.FromContext(ctx).Debugw("request authentication backend skipped", "source", AuthenticationSourceOIDC, "reason", "disabled")
	}

	if a.Config.KubernetesFallbackEnabled() {
		result, err := a.authenticateKubernetes(ctx, rawToken)
		if err == nil {
			logging.FromContext(ctx).Infow("request authentication backend succeeded", "source", AuthenticationSourceKubernetes, "user", result.User.GetName())
			return result, nil
		}
		logging.FromContext(ctx).Warnw("request authentication backend failed", "source", AuthenticationSourceKubernetes, "error", err)
		failures = append(failures, backendFailure{source: AuthenticationSourceKubernetes, err: err})
	} else {
		logging.FromContext(ctx).Debugw("request authentication backend skipped", "source", AuthenticationSourceKubernetes, "reason", "disabled")
	}

	return nil, authenticationFailureError(failures)
}

// AuthenticateAndAuthorize authenticates a bearer token and checks one access request.
func (a *Authenticator) AuthenticateAndAuthorize(ctx context.Context, rawToken string, attrs *AccessAttributes, reviewer SubjectAccessReviewer) (*AuthenticationResult, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, apierrors.NewUnauthorized("a Bearer token must be provided")
	}
	if attrs == nil || (attrs.ResourceAttributes == nil && attrs.NonResourceAttributes == nil) {
		return nil, fmt.Errorf("access attributes are nil")
	}

	failures := []backendFailure{}
	if a.Config.PlatformAuthenticationEnabled() {
		result, err := a.authenticatePlatform(ctx, rawToken)
		if err != nil {
			logging.FromContext(ctx).Warnw("request authentication backend failed", "source", AuthenticationSourcePlatform, "error", err)
			failures = append(failures, backendFailure{source: AuthenticationSourcePlatform, err: err})
		} else {
			if err := a.authorizePlatform(ctx, rawToken, attrs); err != nil {
				logging.FromContext(ctx).Warnw("request authorization backend failed", "source", AuthenticationSourcePlatform, "user", result.User.GetName(), "error", err)
				return nil, err
			}
			logging.FromContext(ctx).Infow("request authentication and authorization backend succeeded", "source", AuthenticationSourcePlatform, "user", result.User.GetName())
			return result, nil
		}
	} else {
		logging.FromContext(ctx).Debugw("request authentication and authorization backend skipped", "source", AuthenticationSourcePlatform, "reason", "disabled or missing platformURL/clusterName")
	}

	if a.Config.OIDCAuthenticationEnabled() {
		result, err := a.authenticateOIDC(ctx, rawToken)
		if err == nil {
			err = reviewAuthenticatedAccess(ctx, reviewer, result.User, attrs)
		}
		if err == nil {
			logging.FromContext(ctx).Infow("request authentication and authorization backend succeeded", "source", AuthenticationSourceOIDC, "user", result.User.GetName())
			return result, nil
		}
		logging.FromContext(ctx).Warnw("request authentication and authorization backend failed", "source", AuthenticationSourceOIDC, "error", err)
		failures = append(failures, backendFailure{source: AuthenticationSourceOIDC, err: err})
	} else {
		logging.FromContext(ctx).Debugw("request authentication and authorization backend skipped", "source", AuthenticationSourceOIDC, "reason", "disabled")
	}

	if a.Config.KubernetesFallbackEnabled() {
		result, err := a.authenticateKubernetes(ctx, rawToken)
		if err == nil {
			err = reviewAuthenticatedAccess(ctx, reviewer, result.User, attrs)
		}
		if err == nil {
			logging.FromContext(ctx).Infow("request authentication and authorization backend succeeded", "source", AuthenticationSourceKubernetes, "user", result.User.GetName())
			return result, nil
		}
		logging.FromContext(ctx).Warnw("request authentication and authorization backend failed", "source", AuthenticationSourceKubernetes, "error", err)
		failures = append(failures, backendFailure{source: AuthenticationSourceKubernetes, err: err})
	} else {
		logging.FromContext(ctx).Debugw("request authentication and authorization backend skipped", "source", AuthenticationSourceKubernetes, "reason", "disabled")
	}

	return nil, authenticationFailureError(failures)
}

// authenticatePlatform validates a token through platform SelfSubjectReview.
func (a *Authenticator) authenticatePlatform(ctx context.Context, rawToken string) (*AuthenticationResult, error) {
	if !a.Config.PlatformConfigured() {
		return nil, fmt.Errorf("platformURL and clusterName are required for platform authentication")
	}
	reviewer, err := a.platformReviewer()
	if err != nil {
		return nil, err
	}
	status, err := reviewer.ReviewSelfSubject(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if status == nil || strings.TrimSpace(status.UserInfo.Username) == "" {
		return nil, apierrors.NewUnauthorized("platform SelfSubjectReview did not authenticate the token")
	}
	return &AuthenticationResult{
		User:   userInfoFromAuthentication(status.UserInfo),
		Source: AuthenticationSourcePlatform,
	}, nil
}

// authorizePlatform checks access for an already authenticated platform token.
func (a *Authenticator) authorizePlatform(ctx context.Context, rawToken string, attrs *AccessAttributes) error {
	reviewer, err := a.platformReviewer()
	if err != nil {
		return err
	}
	status, err := reviewer.ReviewSelfSubjectAccess(ctx, rawToken, attrs)
	if err != nil {
		return err
	}
	if status == nil || !status.Allowed {
		return accessDeniedError(attrs, status)
	}
	return nil
}

// authenticateOIDC validates a token through OIDC discovery and JWKS verification.
func (a *Authenticator) authenticateOIDC(ctx context.Context, rawToken string) (*AuthenticationResult, error) {
	verifier, err := a.oidcVerifier(ctx)
	if err != nil {
		return nil, apierrors.NewServiceUnavailable(fmt.Sprintf("OIDC discovery failed: %v", err))
	}

	verifyCtx, cancel := context.WithTimeout(ctx, a.Config.oidcRequestTimeout())
	defer cancel()

	oidcCtx := oidc.ClientContext(verifyCtx, a.httpClient)
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
		User:   userInfoFromAuthentication(status.User),
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

	discoveryCtx, cancel := context.WithTimeout(ctx, a.Config.oidcRequestTimeout())
	defer cancel()

	oidcCtx := oidc.ClientContext(discoveryCtx, a.httpClient)
	provider, err := oidc.NewProvider(oidcCtx, a.Config.IssuerURL)
	if err != nil {
		return nil, err
	}
	// go-oidc stores the verifier context as a configuration bag for JWKS requests.
	// Use a background context so request-scoped values are not cached in the verifier.
	jwksCtx := oidc.ClientContext(context.Background(), a.httpClient)
	a.verifier = provider.VerifierContext(jwksCtx, &oidc.Config{
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

// platformReviewer returns the configured or lazily constructed platform backend.
func (a *Authenticator) platformReviewer() (PlatformReviewer, error) {
	a.platformOnce.Do(func() {
		if a.platform != nil {
			return
		}
		reviewer, err := NewPlatformKubernetesReviewer(a.Config, a.restConfig)
		if err != nil {
			a.platformErr = err
			return
		}
		a.platform = reviewer
	})
	if a.platformErr != nil {
		return nil, a.platformErr
	}
	return a.platform, nil
}

// reviewAuthenticatedAccess checks access for an already authenticated identity.
func reviewAuthenticatedAccess(ctx context.Context, reviewer SubjectAccessReviewer, info user.Info, attrs *AccessAttributes) error {
	if reviewer == nil {
		return fmt.Errorf("SubjectAccessReviewer is nil")
	}
	return reviewer.Review(ctx, info, attrs)
}

// userInfoFromAuthentication converts Kubernetes authentication user info to apiserver user info.
func userInfoFromAuthentication(info authnv1.UserInfo) user.Info {
	return &user.DefaultInfo{
		Name:   info.Username,
		UID:    info.UID,
		Groups: append([]string{}, info.Groups...),
		Extra:  tokenReviewExtra(info.Extra),
	}
}

// backendFailure stores one failed backend attempt.
type backendFailure struct {
	// source identifies the failed backend.
	source AuthenticationSource
	// err is the backend failure.
	err error
}

// authenticationFailureError returns the final error after all enabled backends fail.
func authenticationFailureError(failures []backendFailure) error {
	if len(failures) == 0 {
		return apierrors.NewUnauthorized("no request authentication backend is enabled")
	}
	if len(failures) == 1 {
		return failures[0].err
	}
	parts := make([]string, 0, len(failures))
	for _, failure := range failures {
		if failure.err == nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s", failure.source, failure.err.Error()))
	}
	if len(parts) == 0 {
		return apierrors.NewUnauthorized("all request authentication backends failed")
	}
	return apierrors.NewUnauthorized(fmt.Sprintf("all request authentication backends failed: %s", strings.Join(parts, "; ")))
}

// accessDeniedError converts a review denial into a Kubernetes forbidden error.
func accessDeniedError(attrs *AccessAttributes, status *authv1.SubjectAccessReviewStatus) error {
	resource := schema.GroupResource{Group: "authorization.k8s.io", Resource: "subjectaccessreviews"}
	name := ""
	verb := ""
	if attrs != nil && attrs.ResourceAttributes != nil {
		resource = schema.GroupResource{
			Group:    attrs.ResourceAttributes.Group,
			Resource: attrs.ResourceAttributes.Resource,
		}
		name = attrs.ResourceAttributes.Name
		verb = attrs.ResourceAttributes.Verb
	}
	if attrs != nil && attrs.NonResourceAttributes != nil {
		name = attrs.NonResourceAttributes.Path
		verb = attrs.NonResourceAttributes.Verb
	}

	message := fmt.Sprintf("access not allowed, verb=%s", verb)
	if status != nil && status.EvaluationError != "" {
		message = fmt.Sprintf("%s, evaluationError=%s", message, status.EvaluationError)
	}
	if status != nil && status.Reason != "" {
		message = fmt.Sprintf("%s, reason=%s", message, status.Reason)
	}
	return apierrors.NewForbidden(resource, name, fmt.Errorf("%s", message))
}
