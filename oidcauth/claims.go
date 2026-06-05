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
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/authentication/user"
)

// VerifiedToken stores claims from a verified OIDC token.
type VerifiedToken struct {
	// Issuer is the verified token issuer.
	Issuer string
	// Subject is the verified token subject.
	Subject string
	// Audience is the verified token audience list.
	Audience []string
	// Claims stores the full verified claim set.
	Claims map[string]any
}

// KubernetesIdentityFromClaims maps verified claims to Kubernetes user.Info.
func KubernetesIdentityFromClaims(config Config, token *VerifiedToken) (user.Info, error) {
	if token == nil {
		return nil, apierrors.NewUnauthorized("verified token is nil")
	}

	name, err := usernameFromClaims(config, token.Claims)
	if err != nil {
		return nil, err
	}

	return &user.DefaultInfo{
		Name:   config.UserPrefix + name,
		Groups: groupsFromClaims(config, token.Claims),
	}, nil
}

// ValidateVerifiedClaims validates token audiences, required claims, and time claims.
func ValidateVerifiedClaims(config Config, token *VerifiedToken) error {
	if token == nil {
		return apierrors.NewUnauthorized("verified token is nil")
	}
	if err := validateAudiences(config.Audiences, token.Audience); err != nil {
		return err
	}
	if err := validateRequiredClaims(config.RequiredClaims, token.Claims); err != nil {
		return err
	}
	return validateTimeClaims(config, token.Claims)
}

// usernameFromClaims returns the first configured non-empty username claim.
func usernameFromClaims(config Config, claims map[string]any) (string, error) {
	for _, claim := range config.UsernameClaims {
		value, ok := stringClaim(claims, claim)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		if claim == "email" && config.RequireEmailVerified {
			if verified, ok := boolClaim(claims, "email_verified"); !ok || !verified {
				return "", apierrors.NewUnauthorized("email claim is not verified")
			}
		}
		return value, nil
	}
	return "", apierrors.NewUnauthorized("no configured username claim was found")
}

// groupsFromClaims maps configured group and role claims to Kubernetes groups.
func groupsFromClaims(config Config, claims map[string]any) []string {
	seen := map[string]struct{}{}
	groups := []string{}
	for _, claim := range append([]string{}, config.GroupsClaims...) {
		for _, value := range stringSliceClaim(claims, claim) {
			group := config.GroupPrefix + value
			if _, ok := seen[group]; ok {
				continue
			}
			seen[group] = struct{}{}
			groups = append(groups, group)
		}
	}
	for _, claim := range config.RolesClaims {
		for _, value := range stringSliceClaim(claims, claim) {
			group := config.GroupPrefix + value
			if _, ok := seen[group]; ok {
				continue
			}
			seen[group] = struct{}{}
			groups = append(groups, group)
		}
	}
	sort.Strings(groups)
	return groups
}

// validateAudiences returns nil when any token audience is accepted.
func validateAudiences(accepted []string, actual []string) error {
	if len(accepted) == 0 {
		return fmt.Errorf("OIDC audiences are not configured")
	}

	for _, want := range accepted {
		for _, got := range actual {
			if want == got {
				return nil
			}
		}
	}
	return apierrors.NewUnauthorized("token audience is not accepted")
}

// validateRequiredClaims checks exact string matches for required claims.
func validateRequiredClaims(required map[string]string, claims map[string]any) error {
	for key, want := range required {
		got, ok := stringClaim(claims, key)
		if !ok || got != want {
			return apierrors.NewUnauthorized(fmt.Sprintf("required claim %s is not satisfied", key))
		}
	}
	return nil
}

// validateTimeClaims checks exp, nbf, and future iat using configured clock skew.
func validateTimeClaims(config Config, claims map[string]any) error {
	now := time.Now
	if config.Now != nil {
		now = config.Now
	}
	nowTime := now()
	skew := config.ClockSkew
	if skew == 0 {
		skew = defaultClockSkew
	}

	exp, ok := numericDateClaim(claims, "exp")
	if !ok {
		return apierrors.NewUnauthorized("token exp claim is required")
	}
	if nowTime.After(exp.Add(skew)) {
		return apierrors.NewUnauthorized("token is expired")
	}

	if nbf, ok := numericDateClaim(claims, "nbf"); ok && nowTime.Add(skew).Before(nbf) {
		return apierrors.NewUnauthorized("token is not valid yet")
	}
	if iat, ok := numericDateClaim(claims, "iat"); ok && nowTime.Add(skew).Before(iat) {
		return apierrors.NewUnauthorized("token issued-at time is in the future")
	}

	return nil
}

// stringClaim returns a string claim value.
func stringClaim(claims map[string]any, name string) (string, bool) {
	value, ok := claims[name]
	if !ok || value == nil {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return typed, true
	case fmt.Stringer:
		return typed.String(), true
	default:
		return "", false
	}
}

// boolClaim returns a bool claim value.
func boolClaim(claims map[string]any, name string) (bool, bool) {
	value, ok := claims[name]
	if !ok || value == nil {
		return false, false
	}
	typed, ok := value.(bool)
	return typed, ok
}

// stringSliceClaim returns a string slice claim value.
func stringSliceClaim(claims map[string]any, name string) []string {
	value, ok := claims[name]
	if !ok || value == nil {
		return nil
	}

	switch typed := value.(type) {
	case []string:
		return compactStrings(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok {
				values = append(values, str)
			}
		}
		return compactStrings(values)
	case string:
		values := strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n'
		})
		return compactStrings(values)
	default:
		return nil
	}
}

// compactStrings trims and drops empty strings.
func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

// numericDateClaim returns a JWT numeric date claim as time.
func numericDateClaim(claims map[string]any, name string) (time.Time, bool) {
	value, ok := claims[name]
	if !ok || value == nil {
		return time.Time{}, false
	}

	var seconds int64
	switch typed := value.(type) {
	case float64:
		seconds = int64(typed)
	case float32:
		seconds = int64(typed)
	case int64:
		seconds = typed
	case int:
		seconds = int64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			floatValue, floatErr := strconv.ParseFloat(typed.String(), 64)
			if floatErr != nil {
				return time.Time{}, false
			}
			seconds = int64(floatValue)
			break
		}
		seconds = parsed
	default:
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}
