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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	authnv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	apiserverrequest "k8s.io/apiserver/pkg/endpoints/request"
)

// fakeTokenReviewer returns a configured TokenReview status for tests.
type fakeTokenReviewer struct {
	// status is returned from ReviewToken.
	status *authnv1.TokenReviewStatus
	// err is returned from ReviewToken.
	err error
	// audiences records the audiences passed to ReviewToken.
	audiences []string
}

// ReviewToken returns the configured fake TokenReview result.
func (r *fakeTokenReviewer) ReviewToken(_ context.Context, _ string, audiences []string) (*authnv1.TokenReviewStatus, error) {
	r.audiences = append([]string{}, audiences...)
	return r.status, r.err
}

// fakeSubjectAccessReviewer records SAR filter inputs for tests.
type fakeSubjectAccessReviewer struct {
	// user records the user passed to Review.
	user user.Info
	// attrs records the attributes passed to Review.
	attrs *AccessAttributes
	// err is returned from Review.
	err error
}

// Review records the inputs and returns the configured error.
func (r *fakeSubjectAccessReviewer) Review(_ context.Context, info user.Info, attrs *AccessAttributes) error {
	r.user = info
	r.attrs = attrs
	return r.err
}

// TestBearerTokenFromRequest verifies Authorization header parsing.
func TestBearerTokenFromRequest(t *testing.T) {
	req := restful.NewRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	if _, err := BearerTokenFromRequest(req); !apierrors.IsUnauthorized(err) {
		t.Fatalf("BearerTokenFromRequest() error = %v, want unauthorized", err)
	}

	req.Request.Header.Set(AuthorizationHeader, "Bearer token-1")
	token, err := BearerTokenFromRequest(req)
	if err != nil {
		t.Fatalf("BearerTokenFromRequest() error = %v", err)
	}
	if token != "token-1" {
		t.Fatalf("token = %q, want token-1", token)
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
	wantGroups := []string{"oidc:role-a", "oidc:role-b", "oidc:team-a", "oidc:team-b"}
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
		IssuerURL: server.URL,
		Audiences: []string{"client"},
		Now:       func() time.Time { return now },
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
		IssuerURL: server.URL,
		Audiences: []string{"client"},
		Now:       func() time.Time { return now },
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	_, err = authenticator.Authenticate(context.Background(), rawToken)
	if !apierrors.IsUnauthorized(err) {
		t.Fatalf("Authenticate() error = %v, want unauthorized", err)
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
