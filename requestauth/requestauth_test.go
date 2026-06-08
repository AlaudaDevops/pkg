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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	authnv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	apiserverrequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// fakeTokenReviewer returns a configured TokenReview status for tests.
type fakeTokenReviewer struct {
	// status is returned from ReviewToken.
	status *authnv1.TokenReviewStatus
	// err is returned from ReviewToken.
	err error
	// audiences records the audiences passed to ReviewToken.
	audiences []string
	// calls records ReviewToken calls.
	calls int
}

// ReviewToken returns the configured fake TokenReview result.
func (r *fakeTokenReviewer) ReviewToken(_ context.Context, _ string, audiences []string) (*authnv1.TokenReviewStatus, error) {
	r.calls++
	r.audiences = append([]string{}, audiences...)
	return r.status, r.err
}

// fakePlatformReviewer returns configured platform self-review statuses for tests.
type fakePlatformReviewer struct {
	// selfStatus is returned from ReviewSelfSubject.
	selfStatus *authnv1.SelfSubjectReviewStatus
	// selfErr is returned from ReviewSelfSubject.
	selfErr error
	// accessStatus is returned from ReviewSelfSubjectAccess.
	accessStatus *authv1.SubjectAccessReviewStatus
	// accessErr is returned from ReviewSelfSubjectAccess.
	accessErr error
	// selfCalls records ReviewSelfSubject calls.
	selfCalls int
	// accessCalls records ReviewSelfSubjectAccess calls.
	accessCalls int
	// accessAttrs records the attributes passed to ReviewSelfSubjectAccess.
	accessAttrs *AccessAttributes
}

// ReviewSelfSubject returns the configured fake platform authentication result.
func (r *fakePlatformReviewer) ReviewSelfSubject(_ context.Context, _ string) (*authnv1.SelfSubjectReviewStatus, error) {
	r.selfCalls++
	return r.selfStatus, r.selfErr
}

// ReviewSelfSubjectAccess returns the configured fake platform authorization result.
func (r *fakePlatformReviewer) ReviewSelfSubjectAccess(_ context.Context, _ string, attrs *AccessAttributes) (*authv1.SubjectAccessReviewStatus, error) {
	r.accessCalls++
	r.accessAttrs = attrs
	return r.accessStatus, r.accessErr
}

// fakeSubjectAccessReviewer records SAR filter inputs for tests.
type fakeSubjectAccessReviewer struct {
	// user records the user passed to Review.
	user user.Info
	// attrs records the attributes passed to Review.
	attrs *AccessAttributes
	// calls records Review calls.
	calls int
	// err is returned from Review.
	err error
}

// Review records the inputs and returns the configured error.
func (r *fakeSubjectAccessReviewer) Review(_ context.Context, info user.Info, attrs *AccessAttributes) error {
	r.calls++
	r.user = info
	r.attrs = attrs
	return r.err
}

// fakeTokenAuthenticator returns configured authentication results for filter tests.
type fakeTokenAuthenticator struct {
	// result is returned from Authenticate.
	result *AuthenticationResult
	// err is returned from Authenticate.
	err error
	// rawToken records the token passed to Authenticate.
	rawToken string
	// calls records Authenticate calls.
	calls int
}

// Authenticate returns the configured fake authentication result.
func (a *fakeTokenAuthenticator) Authenticate(_ context.Context, rawToken string) (*AuthenticationResult, error) {
	a.calls++
	a.rawToken = rawToken
	return a.result, a.err
}

// fakeTokenAccessAuthenticator returns configured authentication and authorization results.
type fakeTokenAccessAuthenticator struct {
	// result is returned from AuthenticateAndAuthorize.
	result *AuthenticationResult
	// err is returned from AuthenticateAndAuthorize.
	err error
	// rawToken records the token passed to AuthenticateAndAuthorize.
	rawToken string
	// attrs records access attributes passed to AuthenticateAndAuthorize.
	attrs *AccessAttributes
	// reviewer records the reviewer passed to AuthenticateAndAuthorize.
	reviewer SubjectAccessReviewer
	// calls records AuthenticateAndAuthorize calls.
	calls int
}

// Authenticate returns the configured fake authentication result.
func (a *fakeTokenAccessAuthenticator) Authenticate(_ context.Context, rawToken string) (*AuthenticationResult, error) {
	a.rawToken = rawToken
	return a.result, a.err
}

// AuthenticateAndAuthorize returns the configured fake access result.
func (a *fakeTokenAccessAuthenticator) AuthenticateAndAuthorize(_ context.Context, rawToken string, attrs *AccessAttributes, reviewer SubjectAccessReviewer) (*AuthenticationResult, error) {
	a.calls++
	a.rawToken = rawToken
	a.attrs = attrs
	a.reviewer = reviewer
	return a.result, a.err
}

// testAuthProviderPersister records auth provider persistence calls in tests.
type testAuthProviderPersister struct{}

// Persist satisfies rest.AuthProviderConfigPersister for credential-copy tests.
func (testAuthProviderPersister) Persist(_ map[string]string) error {
	return nil
}

// oidcRequestContextKey marks request-scoped context values in OIDC verifier tests.
type oidcRequestContextKey struct{}

// contextRecordingRoundTripper records request context values for selected OIDC requests.
type contextRecordingRoundTripper struct {
	// base sends HTTP requests after recording context values.
	base http.RoundTripper
	// mu protects jwksValues.
	mu sync.Mutex
	// jwksValues records marker values seen on JWKS HTTP request contexts.
	jwksValues []any
}

// RoundTrip records JWKS request context values before delegating to the base transport.
func (r *contextRecordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/keys" {
		r.mu.Lock()
		r.jwksValues = append(r.jwksValues, req.Context().Value(oidcRequestContextKey{}))
		r.mu.Unlock()
	}
	base := r.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// JWKSValues returns recorded marker values from JWKS request contexts.
func (r *contextRecordingRoundTripper) JWKSValues() []any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]any{}, r.jwksValues...)
}

// TestBearerTokenFromRequest verifies Authorization header parsing.
func TestBearerTokenFromRequest(t *testing.T) {
	tests := []struct {
		// name identifies the test case.
		name string
		// authorization stores the request Authorization header value.
		authorization string
		// wantToken is the bearer token expected from the request.
		wantToken string
		// wantUnauthorized records whether parsing should reject the request.
		wantUnauthorized bool
	}{
		{
			name:             "missing header",
			wantUnauthorized: true,
		},
		{
			name:          "canonical bearer scheme",
			authorization: "Bearer token-1",
			wantToken:     "token-1",
		},
		{
			name:          "lowercase bearer scheme",
			authorization: "bearer token-1",
			wantToken:     "token-1",
		},
		{
			name:          "mixed case bearer scheme",
			authorization: "bEaReR token-1",
			wantToken:     "token-1",
		},
		{
			name:             "non bearer scheme",
			authorization:    "Basic token-1",
			wantUnauthorized: true,
		},
		{
			name:             "empty token",
			authorization:    "Bearer ",
			wantUnauthorized: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := restful.NewRequest(httptest.NewRequest(http.MethodGet, "/", nil))
			if tt.authorization != "" {
				req.Request.Header.Set(AuthorizationHeader, tt.authorization)
			}

			token, err := BearerTokenFromRequest(req)
			if tt.wantUnauthorized {
				if !apierrors.IsUnauthorized(err) {
					t.Fatalf("BearerTokenFromRequest() error = %v, want unauthorized", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("BearerTokenFromRequest() error = %v", err)
			}
			if token != tt.wantToken {
				t.Fatalf("token = %q, want %s", token, tt.wantToken)
			}
		})
	}
}

// TestClaimsMappingAndValidation verifies OIDC claim validation and Kubernetes identity mapping.
func TestClaimsMappingAndValidation(t *testing.T) {
	now := time.Unix(2000, 0)
	config := Config{
		Audiences:           []string{"client"},
		UsernameClaims:      []string{"preferred_username", "email"},
		GroupsClaims:        []string{"groups"},
		RolesClaims:         []string{"roles"},
		UserPrefix:          "oidc:",
		GroupPrefix:         "oidc:",
		ClockSkew:           time.Minute,
		Now:                 func() time.Time { return now },
		RequiredClaims:      map[string]string{"tenant": "default"},
		KubernetesAudiences: []string{"kubernetes"},
	}
	token := &VerifiedToken{
		Issuer:   "https://issuer.example.com",
		Subject:  "sub-1",
		Audience: []string{"client"},
		Claims: map[string]any{
			"preferred_username": "dev",
			"groups":             []any{"team-a", "team-b"},
			"roles":              "role-a,role-b",
			"tenant":             "default",
			"exp":                float64(now.Add(time.Hour).Unix()),
			"iat":                float64(now.Unix()),
		},
	}

	if err := ValidateVerifiedClaims(config, token); err != nil {
		t.Fatalf("ValidateVerifiedClaims() error = %v", err)
	}
	info, err := KubernetesIdentityFromClaims(config, token)
	if err != nil {
		t.Fatalf("KubernetesIdentityFromClaims() error = %v", err)
	}
	if info.GetName() != "oidc:dev" {
		t.Fatalf("name = %q, want oidc:dev", info.GetName())
	}
	wantGroups := []string{"oidc:role-a", "oidc:role-b", "oidc:team-a", "oidc:team-b", "system:authenticated"}
	if got := fmt.Sprintf("%v", info.GetGroups()); got != fmt.Sprintf("%v", wantGroups) {
		t.Fatalf("groups = %v, want %v", info.GetGroups(), wantGroups)
	}
}

// TestKubernetesIdentityFromClaimsRejectsReservedUsername verifies reserved usernames are not trusted from OIDC claims.
func TestKubernetesIdentityFromClaimsRejectsReservedUsername(t *testing.T) {
	token := &VerifiedToken{
		Claims: map[string]any{
			"preferred_username": "system:serviceaccount:ns:default",
		},
	}

	_, err := KubernetesIdentityFromClaims(Config{
		UsernameClaims: []string{"preferred_username"},
	}, token)
	if !apierrors.IsUnauthorized(err) {
		t.Fatalf("KubernetesIdentityFromClaims() error = %v, want unauthorized", err)
	}
}

// TestKubernetesIdentityFromClaimsRejectsReservedClaimGroups verifies reserved groups are not trusted from OIDC claims.
func TestKubernetesIdentityFromClaimsRejectsReservedClaimGroups(t *testing.T) {
	tests := []struct {
		// name identifies the test case.
		name string
		// config stores the OIDC claim mapping config.
		config Config
		// claims stores the verified OIDC claims.
		claims map[string]any
	}{
		{
			name: "groups claim contains system masters",
			config: Config{
				UsernameClaims: []string{"preferred_username"},
				GroupsClaims:   []string{"groups"},
			},
			claims: map[string]any{
				"preferred_username": "dev",
				"groups":             []any{"team-a", "system:masters"},
			},
		},
		{
			name: "roles claim contains authenticated group",
			config: Config{
				UsernameClaims: []string{"preferred_username"},
				RolesClaims:    []string{"roles"},
			},
			claims: map[string]any{
				"preferred_username": "dev",
				"roles":              "role-a,system:authenticated",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &VerifiedToken{Claims: tt.claims}

			_, err := KubernetesIdentityFromClaims(tt.config, token)
			if !apierrors.IsUnauthorized(err) {
				t.Fatalf("KubernetesIdentityFromClaims() error = %v, want unauthorized", err)
			}
		})
	}
}

// TestKubernetesIdentityFromClaimsAllowsPrefixedReservedClaimValues verifies safe prefixes avoid reserved identities.
func TestKubernetesIdentityFromClaimsAllowsPrefixedReservedClaimValues(t *testing.T) {
	token := &VerifiedToken{
		Claims: map[string]any{
			"preferred_username": "dev",
			"groups":             []any{"system:masters"},
		},
	}

	info, err := KubernetesIdentityFromClaims(Config{
		UsernameClaims: []string{"preferred_username"},
		GroupsClaims:   []string{"groups"},
		GroupPrefix:    "oidc:",
	}, token)
	if err != nil {
		t.Fatalf("KubernetesIdentityFromClaims() error = %v", err)
	}

	wantGroups := []string{"oidc:system:masters", "system:authenticated"}
	if got := fmt.Sprintf("%v", info.GetGroups()); got != fmt.Sprintf("%v", wantGroups) {
		t.Fatalf("groups = %v, want %v", info.GetGroups(), wantGroups)
	}
}

// TestClaimsValidationAudienceMismatch verifies invalid audience handling.
func TestClaimsValidationAudienceMismatch(t *testing.T) {
	token := &VerifiedToken{
		Audience: []string{"other"},
		Claims: map[string]any{
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		},
	}
	err := ValidateVerifiedClaims(Config{Audiences: []string{"client"}}, token)
	if !apierrors.IsUnauthorized(err) {
		t.Fatalf("ValidateVerifiedClaims() error = %v, want unauthorized", err)
	}
}

// TestAuthenticatorOIDC verifies discovery, JWKS signature validation, claims validation, and mapping.
func TestAuthenticatorOIDC(t *testing.T) {
	now := time.Unix(2000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	server := newOIDCTestServer(t, key)
	defer server.Close()

	rawToken := signedOIDCToken(t, key, jwt.MapClaims{
		"iss":                server.URL,
		"sub":                "sub-1",
		"aud":                "client",
		"preferred_username": "dev",
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
	})
	authenticator, err := NewAuthenticator(Config{
		OIDCAuthentication: OIDCAuthenticationEnabled,
		IssuerURL:          server.URL,
		Audiences:          []string{"client"},
		Now:                func() time.Time { return now },
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	result, err := authenticator.Authenticate(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.Source != AuthenticationSourceOIDC {
		t.Fatalf("source = %s, want %s", result.Source, AuthenticationSourceOIDC)
	}
	if result.User.GetName() != "dev" {
		t.Fatalf("user = %q, want dev", result.User.GetName())
	}
}

// TestConfigHTTPClientUsesOIDCRequestTimeout verifies default clients carry a bounded timeout.
func TestConfigHTTPClientUsesOIDCRequestTimeout(t *testing.T) {
	client, err := Config{OIDCRequestTimeout: 75 * time.Millisecond}.HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient() error = %v", err)
	}
	if client.Timeout != 75*time.Millisecond {
		t.Fatalf("timeout = %v, want 75ms", client.Timeout)
	}

	defaultClient, err := Config{}.HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient() error = %v", err)
	}
	if defaultClient.Timeout != defaultOIDCRequestTimeout {
		t.Fatalf("default timeout = %v, want %v", defaultClient.Timeout, defaultOIDCRequestTimeout)
	}
}

// TestNewAuthenticatorAddsOIDCRequestTimeoutToCustomHTTPClient verifies custom clients get a safe default copy.
func TestNewAuthenticatorAddsOIDCRequestTimeoutToCustomHTTPClient(t *testing.T) {
	timeout := 75 * time.Millisecond
	client := &http.Client{}
	authenticator, err := NewAuthenticator(Config{OIDCRequestTimeout: timeout}, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	if client.Timeout != 0 {
		t.Fatalf("original client timeout = %v, want 0", client.Timeout)
	}
	if authenticator.httpClient == client {
		t.Fatalf("authenticator reused a custom client without timeout")
	}
	if authenticator.httpClient.Timeout != timeout {
		t.Fatalf("authenticator timeout = %v, want %v", authenticator.httpClient.Timeout, timeout)
	}

	configuredClient := &http.Client{Timeout: time.Second}
	configuredAuthenticator, err := NewAuthenticator(Config{OIDCRequestTimeout: timeout}, WithHTTPClient(configuredClient))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	if configuredAuthenticator.httpClient != configuredClient {
		t.Fatalf("authenticator replaced a custom client that already has a timeout")
	}
	if configuredAuthenticator.httpClient.Timeout != time.Second {
		t.Fatalf("configured timeout = %v, want 1s", configuredAuthenticator.httpClient.Timeout)
	}
}

// TestAuthenticatorOIDCDiscoveryUsesRequestTimeout verifies discovery cannot block forever.
func TestAuthenticatorOIDCDiscoveryUsesRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(_ http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-release:
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	defer close(release)

	authenticator, err := NewAuthenticator(Config{
		OIDCAuthentication: OIDCAuthenticationEnabled,
		IssuerURL:          server.URL,
		OIDCRequestTimeout: 25 * time.Millisecond,
		KubernetesFallback: KubernetesFallbackDisabled,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	assertServiceUnavailableWithin(t, func() error {
		_, err := authenticator.Authenticate(context.Background(), "token")
		return err
	})
}

// TestAuthenticatorOIDCJWKSUsesRequestTimeout verifies JWKS refresh cannot block forever.
func TestAuthenticatorOIDCJWKSUsesRequestTimeout(t *testing.T) {
	now := time.Unix(2000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	release := make(chan struct{})
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	defer close(release)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(_ http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-release:
		}
	})

	rawToken := signedOIDCToken(t, key, jwt.MapClaims{
		"iss":                server.URL,
		"sub":                "sub-1",
		"aud":                "client",
		"preferred_username": "dev",
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
	})
	authenticator, err := NewAuthenticator(Config{
		OIDCAuthentication: OIDCAuthenticationEnabled,
		IssuerURL:          server.URL,
		Audiences:          []string{"client"},
		Now:                func() time.Time { return now },
		OIDCRequestTimeout: 25 * time.Millisecond,
		KubernetesFallback: KubernetesFallbackDisabled,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	assertServiceUnavailableWithin(t, func() error {
		_, err := authenticator.Authenticate(context.Background(), rawToken)
		return err
	})
}

// TestAuthenticatorOIDCVerifierDoesNotCacheRequestContextValues verifies cached JWKS clients avoid request-scoped values.
func TestAuthenticatorOIDCVerifierDoesNotCacheRequestContextValues(t *testing.T) {
	now := time.Unix(2000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	server := newOIDCTestServer(t, key)
	defer server.Close()

	client := server.Client()
	recorder := &contextRecordingRoundTripper{base: client.Transport}
	client.Transport = recorder

	rawToken := signedOIDCToken(t, key, jwt.MapClaims{
		"iss":                server.URL,
		"sub":                "sub-1",
		"aud":                "client",
		"preferred_username": "dev",
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
	})
	authenticator, err := NewAuthenticator(Config{
		OIDCAuthentication: OIDCAuthenticationEnabled,
		IssuerURL:          server.URL,
		Audiences:          []string{"client"},
		Now:                func() time.Time { return now },
	}, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	ctx := context.WithValue(context.Background(), oidcRequestContextKey{}, "request-marker")
	if _, err := authenticator.Authenticate(ctx, rawToken); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	values := recorder.JWKSValues()
	if len(values) == 0 {
		t.Fatalf("JWKS request was not recorded")
	}
	for _, value := range values {
		if value != nil {
			t.Fatalf("JWKS request context marker = %v, want nil", value)
		}
	}
}

// TestAuthenticatorOIDCAudienceMismatch verifies OIDC audience rejection.
func TestAuthenticatorOIDCAudienceMismatch(t *testing.T) {
	now := time.Unix(2000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	server := newOIDCTestServer(t, key)
	defer server.Close()

	rawToken := signedOIDCToken(t, key, jwt.MapClaims{
		"iss":                server.URL,
		"sub":                "sub-1",
		"aud":                "other",
		"preferred_username": "dev",
		"exp":                now.Add(time.Hour).Unix(),
	})
	authenticator, err := NewAuthenticator(Config{
		OIDCAuthentication: OIDCAuthenticationEnabled,
		IssuerURL:          server.URL,
		Audiences:          []string{"client"},
		Now:                func() time.Time { return now },
		KubernetesFallback: KubernetesFallbackDisabled,
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	_, err = authenticator.Authenticate(context.Background(), rawToken)
	if !apierrors.IsUnauthorized(err) {
		t.Fatalf("Authenticate() error = %v, want unauthorized", err)
	}
}

// TestAuthenticatorOIDCDisabledByDefault verifies an issuer URL does not enable OIDC by itself.
func TestAuthenticatorOIDCDisabledByDefault(t *testing.T) {
	reviewer := &fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "kubernetes-user",
			},
		},
	}
	authenticator, err := NewAuthenticator(Config{
		IssuerURL: "https://issuer.example.com",
	}, WithTokenReviewer(reviewer))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	result, err := authenticator.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.Source != AuthenticationSourceKubernetes {
		t.Fatalf("source = %s, want %s", result.Source, AuthenticationSourceKubernetes)
	}
	if result.User.GetName() != "kubernetes-user" {
		t.Fatalf("user = %q, want kubernetes-user", result.User.GetName())
	}
}

// TestAuthenticatorPlatformTakesPriority verifies platform authentication short-circuits later backends.
func TestAuthenticatorPlatformTakesPriority(t *testing.T) {
	platform := &fakePlatformReviewer{
		selfStatus: &authnv1.SelfSubjectReviewStatus{
			UserInfo: authnv1.UserInfo{
				Username: "platform-user",
				Groups:   []string{"platform-group"},
			},
		},
	}
	tokenReviewer := &fakeTokenReviewer{
		err: fmt.Errorf("kubernetes fallback should not be called"),
	}
	authenticator, err := NewAuthenticator(Config{
		PlatformURL:        "https://platform.example.com",
		ClusterName:        "business",
		IssuerURL:          "https://issuer.example.com",
		OIDCAuthentication: OIDCAuthenticationEnabled,
	}, WithPlatformReviewer(platform), WithTokenReviewer(tokenReviewer))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	result, err := authenticator.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.Source != AuthenticationSourcePlatform {
		t.Fatalf("source = %s, want %s", result.Source, AuthenticationSourcePlatform)
	}
	if result.User.GetName() != "platform-user" {
		t.Fatalf("user = %q, want platform-user", result.User.GetName())
	}
	if platform.selfCalls != 1 {
		t.Fatalf("platform self calls = %d, want 1", platform.selfCalls)
	}
	if tokenReviewer.audiences != nil {
		t.Fatalf("token reviewer was called unexpectedly")
	}
}

// TestAuthenticatorFallsBackAfterPlatformFailure verifies failed platform auth tries Kubernetes fallback.
func TestAuthenticatorFallsBackAfterPlatformFailure(t *testing.T) {
	platform := &fakePlatformReviewer{
		selfErr: apierrors.NewUnauthorized("platform rejected token"),
	}
	tokenReviewer := &fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "kubernetes-user",
			},
		},
	}
	authenticator, err := NewAuthenticator(Config{
		PlatformURL: "https://platform.example.com",
		ClusterName: "business",
	}, WithPlatformReviewer(platform), WithTokenReviewer(tokenReviewer))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	result, err := authenticator.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.Source != AuthenticationSourceKubernetes {
		t.Fatalf("source = %s, want %s", result.Source, AuthenticationSourceKubernetes)
	}
	if result.User.GetName() != "kubernetes-user" {
		t.Fatalf("user = %q, want kubernetes-user", result.User.GetName())
	}
	if platform.selfCalls != 1 {
		t.Fatalf("platform self calls = %d, want 1", platform.selfCalls)
	}
}

// TestAuthenticateAndAuthorizeStopsAfterPlatformAccessDenied verifies platform authorization denial is final.
func TestAuthenticateAndAuthorizeStopsAfterPlatformAccessDenied(t *testing.T) {
	platform := &fakePlatformReviewer{
		selfStatus: &authnv1.SelfSubjectReviewStatus{
			UserInfo: authnv1.UserInfo{
				Username: "platform-user",
			},
		},
		accessStatus: &authv1.SubjectAccessReviewStatus{
			Allowed: false,
			Reason:  "denied by platform",
		},
	}
	tokenReviewer := &fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "kubernetes-user",
			},
		},
	}
	authenticator, err := NewAuthenticator(Config{
		PlatformURL: "https://platform.example.com",
		ClusterName: "business",
	}, WithPlatformReviewer(platform), WithTokenReviewer(tokenReviewer))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	currentClusterReviewer := &fakeSubjectAccessReviewer{}
	result, err := authenticator.AuthenticateAndAuthorize(context.Background(), "token", &AccessAttributes{
		NonResourceAttributes: &authorizationPathAttributes,
	}, currentClusterReviewer)
	if !apierrors.IsForbidden(err) {
		t.Fatalf("AuthenticateAndAuthorize() error = %v, want forbidden", err)
	}
	if result != nil {
		t.Fatalf("AuthenticateAndAuthorize() result = %v, want nil", result)
	}
	if platform.selfCalls != 1 || platform.accessCalls != 1 {
		t.Fatalf("platform calls = self:%d access:%d, want 1/1", platform.selfCalls, platform.accessCalls)
	}
	if tokenReviewer.calls != 0 {
		t.Fatalf("token reviewer calls = %d, want 0", tokenReviewer.calls)
	}
	if currentClusterReviewer.calls != 0 {
		t.Fatalf("current-cluster reviewer calls = %d, want 0", currentClusterReviewer.calls)
	}
}

// TestAuthenticateAndAuthorizeFallsBackAfterPlatformAuthenticationFailure verifies authn failures still fall back.
func TestAuthenticateAndAuthorizeFallsBackAfterPlatformAuthenticationFailure(t *testing.T) {
	platform := &fakePlatformReviewer{
		selfErr: apierrors.NewUnauthorized("platform rejected token"),
	}
	tokenReviewer := &fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "kubernetes-user",
			},
		},
	}
	authenticator, err := NewAuthenticator(Config{
		PlatformURL: "https://platform.example.com",
		ClusterName: "business",
	}, WithPlatformReviewer(platform), WithTokenReviewer(tokenReviewer))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	currentClusterReviewer := &fakeSubjectAccessReviewer{}
	result, err := authenticator.AuthenticateAndAuthorize(context.Background(), "token", &AccessAttributes{
		NonResourceAttributes: &authorizationPathAttributes,
	}, currentClusterReviewer)
	if err != nil {
		t.Fatalf("AuthenticateAndAuthorize() error = %v", err)
	}
	if result.Source != AuthenticationSourceKubernetes {
		t.Fatalf("source = %s, want %s", result.Source, AuthenticationSourceKubernetes)
	}
	if platform.selfCalls != 1 || platform.accessCalls != 0 {
		t.Fatalf("platform calls = self:%d access:%d, want 1/0", platform.selfCalls, platform.accessCalls)
	}
	if tokenReviewer.calls != 1 {
		t.Fatalf("token reviewer calls = %d, want 1", tokenReviewer.calls)
	}
	if currentClusterReviewer.calls != 1 {
		t.Fatalf("current-cluster reviewer calls = %d, want 1", currentClusterReviewer.calls)
	}
}

// TestAuthenticatorRejectsInvalidInputs verifies shared token and access attribute validation.
func TestAuthenticatorRejectsInvalidInputs(t *testing.T) {
	authenticator, err := NewAuthenticator(Config{KubernetesFallback: KubernetesFallbackDisabled})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	if _, err := authenticator.Authenticate(context.Background(), " "); !apierrors.IsUnauthorized(err) {
		t.Fatalf("Authenticate() empty token error = %v, want unauthorized", err)
	}
	if _, err := authenticator.AuthenticateAndAuthorize(context.Background(), " ", validAccessAttributes(), nil); !apierrors.IsUnauthorized(err) {
		t.Fatalf("AuthenticateAndAuthorize() empty token error = %v, want unauthorized", err)
	}
	if _, err := authenticator.AuthenticateAndAuthorize(context.Background(), "token", nil, nil); err == nil {
		t.Fatalf("AuthenticateAndAuthorize() nil attrs error = nil")
	}
}

// TestAuthenticationBackendHelpers verifies small authentication helper branches.
func TestAuthenticationBackendHelpers(t *testing.T) {
	token, err := normalizeBearerToken(" token ")
	if err != nil {
		t.Fatalf("normalizeBearerToken() error = %v", err)
	}
	if token != "token" {
		t.Fatalf("normalized token = %q, want token", token)
	}
	if _, err := normalizeBearerToken(""); !apierrors.IsUnauthorized(err) {
		t.Fatalf("normalizeBearerToken() empty error = %v, want unauthorized", err)
	}
	if err := validateAuthenticationResult(nil); !apierrors.IsUnauthorized(err) {
		t.Fatalf("validateAuthenticationResult() nil result error = %v, want unauthorized", err)
	}
	if err := validateAuthenticationResult(&AuthenticationResult{}); !apierrors.IsUnauthorized(err) {
		t.Fatalf("validateAuthenticationResult() nil user error = %v, want unauthorized", err)
	}
	if got := authenticationResultUserName(nil); got != "" {
		t.Fatalf("nil result username = %q, want empty", got)
	}
	if got := authenticationResultUserName(authenticationResultForUser("dev")); got != "dev" {
		t.Fatalf("username = %q, want dev", got)
	}
}

// TestAuthenticationFailureErrorBranches verifies aggregate backend error messages.
func TestAuthenticationFailureErrorBranches(t *testing.T) {
	if err := authenticationFailureError(nil); !apierrors.IsUnauthorized(err) {
		t.Fatalf("authenticationFailureError() empty error = %v, want unauthorized", err)
	}

	singleErr := fmt.Errorf("single backend failed")
	if err := authenticationFailureError([]backendFailure{{source: AuthenticationSourceOIDC, err: singleErr}}); err != singleErr {
		t.Fatalf("single backend error = %v, want original error", err)
	}

	emptyAggregate := authenticationFailureError([]backendFailure{
		{source: AuthenticationSourceOIDC},
		{source: AuthenticationSourceKubernetes},
	})
	if !apierrors.IsUnauthorized(emptyAggregate) || !strings.Contains(emptyAggregate.Error(), "all request authentication backends failed") {
		t.Fatalf("empty aggregate error = %v, want unauthorized aggregate", emptyAggregate)
	}

	combined := authenticationFailureError([]backendFailure{
		{source: AuthenticationSourceOIDC, err: fmt.Errorf("oidc rejected token")},
		{source: AuthenticationSourceKubernetes, err: fmt.Errorf("token review rejected token")},
	})
	if !apierrors.IsUnauthorized(combined) || !strings.Contains(combined.Error(), "oidc rejected token") || !strings.Contains(combined.Error(), "token review rejected token") {
		t.Fatalf("combined error = %v, want both backend failures", combined)
	}
}

// TestPlatformReviewerRestConfigForTokenDropsCopiedCredentials verifies token configs do not inherit base identities.
func TestPlatformReviewerRestConfigForTokenDropsCopiedCredentials(t *testing.T) {
	proxyURL, err := url.Parse("http://proxy.example.com")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	baseConfig := &rest.Config{
		Host: "https://cluster.example.com",
		ContentConfig: rest.ContentConfig{
			AcceptContentTypes: "application/json",
			ContentType:        "application/json",
		},
		Username:        "base-user",
		Password:        "base-password",
		BearerToken:     "base-token",
		BearerTokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		Impersonate: rest.ImpersonationConfig{
			UserName: "impersonated-user",
			UID:      "impersonated-uid",
			Groups:   []string{"impersonated-group"},
			Extra:    map[string][]string{"scope": {"impersonated-scope"}},
		},
		AuthProvider: &clientcmdapi.AuthProviderConfig{
			Name:   "oidc",
			Config: map[string]string{"id-token": "base-id-token"},
		},
		AuthConfigPersister: testAuthProviderPersister{},
		ExecProvider: &clientcmdapi.ExecConfig{
			Command: "credential-plugin",
		},
		TLSClientConfig: rest.TLSClientConfig{
			Insecure:   true,
			ServerName: "platform.internal",
			CertFile:   "/path/to/client.crt",
			KeyFile:    "/path/to/client.key",
			CAFile:     "/path/to/ca.crt",
			CertData:   []byte("client-cert-data"),
			KeyData:    []byte("client-key-data"),
			CAData:     []byte("ca-data"),
			NextProtos: []string{"h2"},
		},
		UserAgent:          "requestauth-test",
		DisableCompression: true,
		Transport:          http.DefaultTransport,
		WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
			return rt
		},
		QPS:     20,
		Burst:   30,
		Timeout: 5 * time.Second,
		Proxy: func(_ *http.Request) (*url.URL, error) {
			return proxyURL, nil
		},
	}
	reviewer := &PlatformKubernetesReviewer{
		BaseConfig:            baseConfig,
		PlatformURL:           "https://platform.example.com",
		ClusterName:           "business",
		InsecureSkipTLSVerify: false,
	}

	config, err := reviewer.restConfigForToken("  request-token  ")
	if err != nil {
		t.Fatalf("restConfigForToken() error = %v", err)
	}
	if config.Host != "https://platform.example.com/kubernetes/business" {
		t.Fatalf("host = %q, want platform route", config.Host)
	}
	if config.BearerToken != "request-token" {
		t.Fatalf("bearer token = %q, want request token", config.BearerToken)
	}
	if config.Username != "" || config.Password != "" || config.BearerTokenFile != "" {
		t.Fatalf("basic or bearer file credentials were copied")
	}
	if config.AuthProvider != nil || config.AuthConfigPersister != nil || config.ExecProvider != nil {
		t.Fatalf("plugin credentials were copied")
	}
	if config.Impersonate.UserName != "" || config.Impersonate.UID != "" || len(config.Impersonate.Groups) != 0 || len(config.Impersonate.Extra) != 0 {
		t.Fatalf("impersonation config was copied: %#v", config.Impersonate)
	}
	if config.TLSClientConfig.CertFile != "" || config.TLSClientConfig.KeyFile != "" || len(config.TLSClientConfig.CertData) != 0 || len(config.TLSClientConfig.KeyData) != 0 {
		t.Fatalf("client certificate credentials were copied")
	}
	if config.TLSClientConfig.Insecure {
		t.Fatalf("insecure TLS was inherited from base config")
	}
	if config.TLSClientConfig.ServerName != "platform.internal" || config.TLSClientConfig.CAFile != "/path/to/ca.crt" || string(config.TLSClientConfig.CAData) != "ca-data" {
		t.Fatalf("CA or server name transport settings were not preserved: %#v", config.TLSClientConfig)
	}
	if len(config.TLSClientConfig.NextProtos) != 1 || config.TLSClientConfig.NextProtos[0] != "h2" {
		t.Fatalf("next protos = %v, want [h2]", config.TLSClientConfig.NextProtos)
	}
	if config.ContentConfig.ContentType != "application/json" || config.UserAgent != "requestauth-test" || !config.DisableCompression {
		t.Fatalf("non-identity request settings were not preserved")
	}
	if config.QPS != 20 || config.Burst != 30 || config.Timeout != 5*time.Second {
		t.Fatalf("rate or timeout settings were not preserved")
	}
	if config.Transport != nil || config.WrapTransport != nil {
		t.Fatalf("custom transport wrappers were copied")
	}
	if config.Proxy == nil {
		t.Fatalf("proxy setting was not preserved")
	}
	gotProxyURL, err := config.Proxy(httptest.NewRequest(http.MethodGet, "https://platform.example.com", nil))
	if err != nil {
		t.Fatalf("Proxy() error = %v", err)
	}
	if gotProxyURL.String() != proxyURL.String() {
		t.Fatalf("proxy URL = %q, want %q", gotProxyURL.String(), proxyURL.String())
	}
}

// TestAuthenticatorKubernetesFallback verifies TokenReview fallback when issuer is not configured.
func TestAuthenticatorKubernetesFallback(t *testing.T) {
	reviewer := &fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "system:serviceaccount:ns:default",
				UID:      "uid-1",
				Groups:   []string{"system:authenticated"},
			},
		},
	}
	authenticator, err := NewAuthenticator(Config{
		KubernetesAudiences: []string{"kubernetes"},
	}, WithTokenReviewer(reviewer))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	result, err := authenticator.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.Source != AuthenticationSourceKubernetes {
		t.Fatalf("source = %s, want %s", result.Source, AuthenticationSourceKubernetes)
	}
	if result.User.GetName() != "system:serviceaccount:ns:default" {
		t.Fatalf("user = %q", result.User.GetName())
	}
	if got := fmt.Sprintf("%v", reviewer.audiences); got != "[kubernetes]" {
		t.Fatalf("audiences = %s, want [kubernetes]", got)
	}
}

// TestKubernetesTokenReviewerLazyInitIsConcurrentSafe verifies concurrent fallback reviewer initialization.
func TestKubernetesTokenReviewerLazyInitIsConcurrentSafe(t *testing.T) {
	authenticator, err := NewAuthenticator(Config{}, WithKubernetesRESTConfig(&rest.Config{
		Host: "https://example.com",
	}))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	const goroutines = 32
	start := make(chan struct{})
	reviewers := make([]TokenReviewer, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		index := i
		go func() {
			defer wg.Done()
			<-start
			reviewers[index], errs[index] = authenticator.kubernetesTokenReviewer()
		}()
	}
	close(start)
	wg.Wait()

	first := reviewers[0]
	if first == nil {
		t.Fatalf("reviewer[0] is nil")
	}
	for index, err := range errs {
		if err != nil {
			t.Fatalf("kubernetesTokenReviewer() error at %d = %v", index, err)
		}
		if reviewers[index] != first {
			t.Fatalf("reviewer[%d] = %p, want %p", index, reviewers[index], first)
		}
	}
}

// TestKubernetesTokenReviewerLazyInitCachesError verifies failed lazy initialization is not retried.
func TestKubernetesTokenReviewerLazyInitCachesError(t *testing.T) {
	authenticator, err := NewAuthenticator(Config{})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	_, firstErr := authenticator.kubernetesTokenReviewer()
	if firstErr == nil {
		t.Fatalf("kubernetesTokenReviewer() error = nil, want REST config error")
	}

	authenticator.restConfig = &rest.Config{Host: "https://example.com"}
	reviewer, secondErr := authenticator.kubernetesTokenReviewer()
	if secondErr == nil {
		t.Fatalf("kubernetesTokenReviewer() error = nil, want cached REST config error")
	}
	if secondErr != firstErr {
		t.Fatalf("second error = %v, want cached error %v", secondErr, firstErr)
	}
	if reviewer != nil {
		t.Fatalf("reviewer = %v, want nil", reviewer)
	}
}

// TestAuthenticationFilterInjectsUser verifies authn-only filter context injection.
func TestAuthenticationFilterInjectsUser(t *testing.T) {
	authenticator, err := NewAuthenticator(Config{}, WithTokenReviewer(&fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "dev",
				Groups:   []string{"system:authenticated"},
			},
		},
	}))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	req := restful.NewRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	req.Request.Header.Set(AuthorizationHeader, "Bearer token")
	resp := restful.NewResponse(httptest.NewRecorder())
	filter := NewAuthenticationFilter(authenticator)

	called := false
	filter(req, resp, &restful.FilterChain{
		Target: func(req *restful.Request, _ *restful.Response) {
			called = true
			info, ok := apiserverrequest.UserFrom(req.Request.Context())
			if !ok || info.GetName() != "dev" {
				t.Fatalf("context user = %v, want dev", info)
			}
		},
	})
	if !called {
		t.Fatalf("filter chain was not called")
	}
}

// TestAuthenticationFilterErrors verifies authentication-only filter error paths.
func TestAuthenticationFilterErrors(t *testing.T) {
	tests := []struct {
		// name identifies the test case.
		name string
		// authenticator stores the fake authenticator used by the filter.
		authenticator TokenAuthenticator
		// authorization stores the request Authorization header value.
		authorization string
		// wantStatus is the expected HTTP response status.
		wantStatus int
	}{
		{
			name:          "nil authenticator",
			authorization: "Bearer token",
			wantStatus:    http.StatusInternalServerError,
		},
		{
			name:          "missing bearer token",
			authenticator: authenticationResultAuthenticator("dev"),
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name: "authenticator error",
			authenticator: &fakeTokenAuthenticator{
				err: apierrors.NewUnauthorized("token rejected"),
			},
			authorization: "Bearer token",
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name: "nil authentication result user",
			authenticator: &fakeTokenAuthenticator{
				result: &AuthenticationResult{},
			},
			authorization: "Bearer token",
			wantStatus:    http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, resp, recorder := newFilterRequest(tt.authorization)
			called := false
			NewAuthenticationFilter(tt.authenticator)(req, resp, &restful.FilterChain{
				Target: func(_ *restful.Request, _ *restful.Response) {
					called = true
				},
			})
			if called {
				t.Fatalf("filter chain was called")
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("response code = %d, want %d", recorder.Code, tt.wantStatus)
			}
		})
	}
}

// TestSubjectAccessReviewFilter verifies authn plus SAR filter behavior.
func TestSubjectAccessReviewFilter(t *testing.T) {
	authenticator, err := NewAuthenticator(Config{}, WithTokenReviewer(&fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "dev",
			},
		},
	}))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	reviewer := &fakeSubjectAccessReviewer{}
	filter := NewSubjectAccessReviewFilter(authenticator, reviewer, AccessAttributesGetterFunc(func(_ context.Context, _ *restful.Request) (*AccessAttributes, error) {
		return &AccessAttributes{
			NonResourceAttributes: &authorizationPathAttributes,
		}, nil
	}))

	req := restful.NewRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	req.Request.Header.Set(AuthorizationHeader, "Bearer token")
	resp := restful.NewResponse(httptest.NewRecorder())

	called := false
	filter(req, resp, &restful.FilterChain{
		Target: func(_ *restful.Request, _ *restful.Response) {
			called = true
		},
	})
	if !called {
		t.Fatalf("filter chain was not called")
	}
	if reviewer.user == nil || reviewer.user.GetName() != "dev" {
		t.Fatalf("reviewer user = %v, want dev", reviewer.user)
	}
	if reviewer.attrs == nil || reviewer.attrs.NonResourceAttributes == nil {
		t.Fatalf("reviewer attrs were not recorded")
	}
}

// TestSubjectAccessReviewFilterAccessAuthenticatorErrors verifies direct access authenticator error paths.
func TestSubjectAccessReviewFilterAccessAuthenticatorErrors(t *testing.T) {
	tests := []struct {
		// name identifies the test case.
		name string
		// authenticator stores the access authenticator used by the filter.
		authenticator *fakeTokenAccessAuthenticator
		// getter stores the attributes getter used by the filter.
		getter AccessAttributesGetter
		// authorization stores the request Authorization header value.
		authorization string
		// wantStatus is the expected HTTP response status.
		wantStatus int
	}{
		{
			name:          "missing bearer token",
			authenticator: accessResultAuthenticator("dev"),
			getter:        staticAccessAttributesGetter(),
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name:          "nil getter",
			authenticator: accessResultAuthenticator("dev"),
			authorization: "Bearer token",
			wantStatus:    http.StatusInternalServerError,
		},
		{
			name:          "getter error",
			authenticator: accessResultAuthenticator("dev"),
			getter: AccessAttributesGetterFunc(func(_ context.Context, _ *restful.Request) (*AccessAttributes, error) {
				return nil, fmt.Errorf("attributes unavailable")
			}),
			authorization: "Bearer token",
			wantStatus:    http.StatusInternalServerError,
		},
		{
			name: "access authenticator error",
			authenticator: &fakeTokenAccessAuthenticator{
				err: apierrors.NewUnauthorized("token rejected"),
			},
			getter:        staticAccessAttributesGetter(),
			authorization: "Bearer token",
			wantStatus:    http.StatusUnauthorized,
		},
		{
			name: "nil authentication result user",
			authenticator: &fakeTokenAccessAuthenticator{
				result: &AuthenticationResult{},
			},
			getter:        staticAccessAttributesGetter(),
			authorization: "Bearer token",
			wantStatus:    http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, resp, recorder := newFilterRequest(tt.authorization)
			called := false
			NewSubjectAccessReviewFilter(tt.authenticator, &fakeSubjectAccessReviewer{}, tt.getter)(req, resp, &restful.FilterChain{
				Target: func(_ *restful.Request, _ *restful.Response) {
					called = true
				},
			})
			if called {
				t.Fatalf("filter chain was called")
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("response code = %d, want %d", recorder.Code, tt.wantStatus)
			}
		})
	}
}

// TestSubjectAccessReviewFilterLegacyErrors verifies two-step authn plus SAR error paths.
func TestSubjectAccessReviewFilterLegacyErrors(t *testing.T) {
	tests := []struct {
		// name identifies the test case.
		name string
		// reviewer stores the reviewer used by the filter.
		reviewer SubjectAccessReviewer
		// getter stores the attributes getter used by the filter.
		getter AccessAttributesGetter
		// wantStatus is the expected HTTP response status.
		wantStatus int
	}{
		{
			name:       "nil reviewer",
			getter:     staticAccessAttributesGetter(),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "nil getter",
			reviewer:   &fakeSubjectAccessReviewer{},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:     "getter error",
			reviewer: &fakeSubjectAccessReviewer{},
			getter: AccessAttributesGetterFunc(func(_ context.Context, _ *restful.Request) (*AccessAttributes, error) {
				return nil, fmt.Errorf("attributes unavailable")
			}),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "reviewer error",
			reviewer: &fakeSubjectAccessReviewer{
				err: apierrors.NewForbidden(schema.GroupResource{Resource: "deployments"}, "web", fmt.Errorf("denied")),
			},
			getter:     staticAccessAttributesGetter(),
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, resp, recorder := newFilterRequest("Bearer token")
			called := false
			NewSubjectAccessReviewFilter(authenticationResultAuthenticator("dev"), tt.reviewer, tt.getter)(req, resp, &restful.FilterChain{
				Target: func(_ *restful.Request, _ *restful.Response) {
					called = true
				},
			})
			if called {
				t.Fatalf("filter chain was called")
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("response code = %d, want %d", recorder.Code, tt.wantStatus)
			}
		})
	}
}

// TestSubjectAccessReviewFilterUsesPlatformSSARFirst verifies platform authorization avoids current-cluster SAR.
func TestSubjectAccessReviewFilterUsesPlatformSSARFirst(t *testing.T) {
	platform := &fakePlatformReviewer{
		selfStatus: &authnv1.SelfSubjectReviewStatus{
			UserInfo: authnv1.UserInfo{
				Username: "platform-user",
			},
		},
		accessStatus: &authv1.SubjectAccessReviewStatus{
			Allowed: true,
		},
	}
	authenticator, err := NewAuthenticator(Config{
		PlatformURL: "https://platform.example.com",
		ClusterName: "business",
	}, WithPlatformReviewer(platform))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	currentClusterReviewer := &fakeSubjectAccessReviewer{}
	filter := NewSubjectAccessReviewFilter(authenticator, currentClusterReviewer, AccessAttributesGetterFunc(func(_ context.Context, _ *restful.Request) (*AccessAttributes, error) {
		return &AccessAttributes{
			NonResourceAttributes: &authorizationPathAttributes,
		}, nil
	}))

	req := restful.NewRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	req.Request.Header.Set(AuthorizationHeader, "Bearer token")
	resp := restful.NewResponse(httptest.NewRecorder())

	called := false
	filter(req, resp, &restful.FilterChain{
		Target: func(req *restful.Request, _ *restful.Response) {
			called = true
			result := AuthenticationResultFromContext(req.Request.Context())
			if result == nil || result.Source != AuthenticationSourcePlatform {
				t.Fatalf("authentication result source = %v, want platform", result)
			}
		},
	})
	if !called {
		t.Fatalf("filter chain was not called")
	}
	if platform.selfCalls != 1 || platform.accessCalls != 1 {
		t.Fatalf("platform calls = self:%d access:%d, want 1/1", platform.selfCalls, platform.accessCalls)
	}
	if platform.accessAttrs == nil || platform.accessAttrs.NonResourceAttributes == nil {
		t.Fatalf("platform access attrs were not recorded")
	}
	if currentClusterReviewer.calls != 0 {
		t.Fatalf("current-cluster reviewer calls = %d, want 0", currentClusterReviewer.calls)
	}
}

// TestSubjectAccessReviewFilterReturnsForbiddenAfterPlatformAccessDenied verifies denied platform SSAR stays 403.
func TestSubjectAccessReviewFilterReturnsForbiddenAfterPlatformAccessDenied(t *testing.T) {
	platform := &fakePlatformReviewer{
		selfStatus: &authnv1.SelfSubjectReviewStatus{
			UserInfo: authnv1.UserInfo{
				Username: "platform-user",
			},
		},
		accessStatus: &authv1.SubjectAccessReviewStatus{
			Allowed: false,
			Reason:  "denied by platform",
		},
	}
	tokenReviewer := &fakeTokenReviewer{
		status: &authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "kubernetes-user",
			},
		},
	}
	authenticator, err := NewAuthenticator(Config{
		PlatformURL: "https://platform.example.com",
		ClusterName: "business",
	}, WithPlatformReviewer(platform), WithTokenReviewer(tokenReviewer))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	currentClusterReviewer := &fakeSubjectAccessReviewer{}
	filter := NewSubjectAccessReviewFilter(authenticator, currentClusterReviewer, AccessAttributesGetterFunc(func(_ context.Context, _ *restful.Request) (*AccessAttributes, error) {
		return &AccessAttributes{
			NonResourceAttributes: &authorizationPathAttributes,
		}, nil
	}))

	called := false
	container := restful.NewContainer()
	service := new(restful.WebService)
	service.Path("/").Produces(restful.MIME_JSON)
	service.Route(service.GET("/").Filter(filter).To(func(_ *restful.Request, _ *restful.Response) {
		called = true
	}))
	container.Add(service)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(AuthorizationHeader, "Bearer token")
	req.Header.Set("Accept", restful.MIME_JSON)
	recorder := httptest.NewRecorder()
	container.ServeHTTP(recorder, req)

	if called {
		t.Fatalf("filter chain was called")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("response code = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if tokenReviewer.calls != 0 {
		t.Fatalf("token reviewer calls = %d, want 0", tokenReviewer.calls)
	}
	if currentClusterReviewer.calls != 0 {
		t.Fatalf("current-cluster reviewer calls = %d, want 0", currentClusterReviewer.calls)
	}
}

// TestSubjectAccessReviewFilterRunsAfterPlatformAccessAllowed verifies container-based filter setup.
func TestSubjectAccessReviewFilterRunsAfterPlatformAccessAllowed(t *testing.T) {
	platform := &fakePlatformReviewer{
		selfStatus: &authnv1.SelfSubjectReviewStatus{
			UserInfo: authnv1.UserInfo{
				Username: "platform-user",
			},
		},
		accessStatus: &authv1.SubjectAccessReviewStatus{
			Allowed: true,
		},
	}
	authenticator, err := NewAuthenticator(Config{
		PlatformURL: "https://platform.example.com",
		ClusterName: "business",
	}, WithPlatformReviewer(platform))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	filter := NewSubjectAccessReviewFilter(authenticator, &fakeSubjectAccessReviewer{}, AccessAttributesGetterFunc(func(_ context.Context, _ *restful.Request) (*AccessAttributes, error) {
		return &AccessAttributes{
			NonResourceAttributes: &authorizationPathAttributes,
		}, nil
	}))

	called := false
	container := restful.NewContainer()
	service := new(restful.WebService)
	service.Path("/").Produces(restful.MIME_JSON)
	service.Route(service.GET("/").Filter(filter).To(func(_ *restful.Request, _ *restful.Response) {
		called = true
	}))
	container.Add(service)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(AuthorizationHeader, "Bearer token")
	req.Header.Set("Accept", restful.MIME_JSON)
	recorder := httptest.NewRecorder()
	container.ServeHTTP(recorder, req)

	if !called {
		t.Fatalf("filter chain was not called")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("response code = %d, want %d", recorder.Code, http.StatusOK)
	}
}

// authenticationResultForUser returns a test authentication result for one username.
func authenticationResultForUser(name string) *AuthenticationResult {
	return &AuthenticationResult{
		User: &user.DefaultInfo{Name: name},
	}
}

// authenticationResultAuthenticator returns a fake authenticator for one username.
func authenticationResultAuthenticator(name string) *fakeTokenAuthenticator {
	return &fakeTokenAuthenticator{
		result: authenticationResultForUser(name),
	}
}

// accessResultAuthenticator returns a fake access authenticator for one username.
func accessResultAuthenticator(name string) *fakeTokenAccessAuthenticator {
	return &fakeTokenAccessAuthenticator{
		result: authenticationResultForUser(name),
	}
}

// validAccessAttributes returns a reusable non-resource access request.
func validAccessAttributes() *AccessAttributes {
	return &AccessAttributes{
		NonResourceAttributes: &authorizationPathAttributes,
	}
}

// staticAccessAttributesGetter returns a getter for a reusable access request.
func staticAccessAttributesGetter() AccessAttributesGetter {
	return AccessAttributesGetterFunc(func(_ context.Context, _ *restful.Request) (*AccessAttributes, error) {
		return validAccessAttributes(), nil
	})
}

// newFilterRequest creates a go-restful request and response for filter tests.
func newFilterRequest(authorization string) (*restful.Request, *restful.Response, *httptest.ResponseRecorder) {
	req := restful.NewRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	req.Request.Header.Set("Accept", restful.MIME_JSON)
	if authorization != "" {
		req.Request.Header.Set(AuthorizationHeader, authorization)
	}
	recorder := httptest.NewRecorder()
	resp := restful.NewResponse(recorder)
	resp.SetRequestAccepts(restful.MIME_JSON)
	return req, resp, recorder
}

// assertServiceUnavailableWithin verifies an OIDC upstream timeout returns promptly.
func assertServiceUnavailableWithin(t *testing.T, run func() error) {
	t.Helper()

	resultCh := make(chan error, 1)
	started := time.Now()
	go func() {
		resultCh <- run()
	}()

	select {
	case err := <-resultCh:
		if !apierrors.IsServiceUnavailable(err) {
			t.Fatalf("Authenticate() error = %v, want service unavailable", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("Authenticate() elapsed = %v, want bounded by OIDC timeout", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatalf("Authenticate() did not return within the OIDC timeout")
	}
}

// authorizationPathAttributes is a reusable non-resource attribute fixture.
var authorizationPathAttributes = authzNonResourceAttributes("/apis/v1alpha1/capabilities", "get")

// authzNonResourceAttributes creates a non-resource attribute fixture.
func authzNonResourceAttributes(path string, verb string) authv1NonResourceAttributes {
	return authv1NonResourceAttributes{Path: path, Verb: verb}
}

// authv1NonResourceAttributes aliases the authorization type for test fixture comments.
type authv1NonResourceAttributes = authv1.NonResourceAttributes

// newOIDCTestServer returns an OIDC discovery and JWKS test server.
func newOIDCTestServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"keys": []map[string]any{rsaJWK(key)},
		})
	})
	return server
}

// signedOIDCToken returns an RS256 JWT signed by the given key.
func signedOIDCToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return raw
}

// rsaJWK returns the public JWK for the test RSA key.
func rsaJWK(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": "test-key",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// writeJSON writes a JSON response in tests.
func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
}
