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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// claimStringer returns a string claim through fmt.Stringer.
type claimStringer string

// String returns the stringer claim value.
func (s claimStringer) String() string {
	return string(s)
}

// TestKubernetesIdentityFromClaimsEmailVerified verifies email verification enforcement.
func TestKubernetesIdentityFromClaimsEmailVerified(t *testing.T) {
	config := Config{
		UsernameClaims:       []string{"email"},
		RequireEmailVerified: true,
	}

	token := &VerifiedToken{
		Claims: map[string]any{
			"email":          "dev@example.com",
			"email_verified": true,
		},
	}
	info, err := KubernetesIdentityFromClaims(config, token)
	if err != nil {
		t.Fatalf("KubernetesIdentityFromClaims() error = %v", err)
	}
	if info.GetName() != "dev@example.com" {
		t.Fatalf("name = %q, want email", info.GetName())
	}

	for _, verified := range []any{false, "true", nil} {
		t.Run(fmt.Sprintf("email_verified_%v", verified), func(t *testing.T) {
			token := &VerifiedToken{
				Claims: map[string]any{
					"email":          "dev@example.com",
					"email_verified": verified,
				},
			}
			if _, err := KubernetesIdentityFromClaims(config, token); !apierrors.IsUnauthorized(err) {
				t.Fatalf("KubernetesIdentityFromClaims() error = %v, want unauthorized", err)
			}
		})
	}
}

// TestValidateVerifiedClaimsTimeBranches verifies exp, nbf, and iat validation errors.
func TestValidateVerifiedClaimsTimeBranches(t *testing.T) {
	now := time.Unix(2000, 0)
	config := Config{
		Audiences: []string{"client"},
		ClockSkew: time.Second,
		Now:       func() time.Time { return now },
	}

	tests := []struct {
		// name identifies the test case.
		name string
		// claims stores token claims.
		claims map[string]any
		// wantUnauthorized records whether validation should reject the token.
		wantUnauthorized bool
	}{
		{
			name: "json number exp",
			claims: map[string]any{
				"exp": json.Number(fmt.Sprintf("%d", now.Add(time.Hour).Unix())),
			},
		},
		{
			name: "missing exp",
			claims: map[string]any{
				"iat": now.Unix(),
			},
			wantUnauthorized: true,
		},
		{
			name: "expired token",
			claims: map[string]any{
				"exp": now.Add(-time.Hour).Unix(),
			},
			wantUnauthorized: true,
		},
		{
			name: "not before in future",
			claims: map[string]any{
				"exp": now.Add(time.Hour).Unix(),
				"nbf": now.Add(time.Hour).Unix(),
			},
			wantUnauthorized: true,
		},
		{
			name: "issued at in future",
			claims: map[string]any{
				"exp": now.Add(time.Hour).Unix(),
				"iat": now.Add(time.Hour).Unix(),
			},
			wantUnauthorized: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &VerifiedToken{
				Audience: []string{"client"},
				Claims:   tt.claims,
			}
			err := ValidateVerifiedClaims(config, token)
			if tt.wantUnauthorized {
				if !apierrors.IsUnauthorized(err) {
					t.Fatalf("ValidateVerifiedClaims() error = %v, want unauthorized", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateVerifiedClaims() error = %v", err)
			}
		})
	}
}

// TestClaimValueHelpers verifies unexported claim conversion helpers.
func TestClaimValueHelpers(t *testing.T) {
	claims := map[string]any{
		"stringer":  claimStringer("dev"),
		"nonString": 10,
		"nil":       nil,
		"groups":    []string{" team-a ", "", "team-b"},
		"roles":     []any{"role-a", 10, " role-b "},
		"scopes":    "read,write audit\nadmin",
		"invalid":   10,
	}

	if got, ok := stringClaim(claims, "stringer"); !ok || got != "dev" {
		t.Fatalf("stringer claim = %q/%v, want dev/true", got, ok)
	}
	for _, name := range []string{"missing", "nil", "nonString"} {
		if got, ok := stringClaim(claims, name); ok || got != "" {
			t.Fatalf("string claim %s = %q/%v, want empty/false", name, got, ok)
		}
	}
	if got := fmt.Sprintf("%v", stringSliceClaim(claims, "groups")); got != "[team-a team-b]" {
		t.Fatalf("groups = %s, want compacted groups", got)
	}
	if got := fmt.Sprintf("%v", stringSliceClaim(claims, "roles")); got != "[role-a role-b]" {
		t.Fatalf("roles = %s, want string roles", got)
	}
	if got := fmt.Sprintf("%v", stringSliceClaim(claims, "scopes")); got != "[read write audit admin]" {
		t.Fatalf("scopes = %s, want split scopes", got)
	}
	if values := stringSliceClaim(claims, "invalid"); values != nil {
		t.Fatalf("invalid slice claim = %v, want nil", values)
	}
}

// TestNumericDateClaim verifies all supported numeric date representations.
func TestNumericDateClaim(t *testing.T) {
	claims := map[string]any{
		"float64":   float64(10),
		"float32":   float32(20),
		"int64":     int64(30),
		"int":       int(40),
		"jsonInt":   json.Number("50"),
		"jsonFloat": json.Number("60.8"),
		"badJSON":   json.Number("bad"),
		"string":    "70",
		"nil":       nil,
	}

	tests := []struct {
		// name identifies the test case and claim key.
		name string
		// wantUnix is the expected Unix timestamp.
		wantUnix int64
		// wantOK records whether the claim should parse.
		wantOK bool
	}{
		{name: "float64", wantUnix: 10, wantOK: true},
		{name: "float32", wantUnix: 20, wantOK: true},
		{name: "int64", wantUnix: 30, wantOK: true},
		{name: "int", wantUnix: 40, wantOK: true},
		{name: "jsonInt", wantUnix: 50, wantOK: true},
		{name: "jsonFloat", wantUnix: 60, wantOK: true},
		{name: "badJSON"},
		{name: "string"},
		{name: "nil"},
		{name: "missing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := numericDateClaim(claims, tt.name)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got.Unix() != tt.wantUnix {
				t.Fatalf("unix = %d, want %d", got.Unix(), tt.wantUnix)
			}
		})
	}
}
