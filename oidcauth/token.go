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
	"strings"

	"github.com/emicklei/go-restful/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// AuthorizationHeader is the HTTP header used for bearer tokens.
	AuthorizationHeader = "Authorization"
	// bearerScheme is the case-insensitive HTTP authentication scheme for bearer tokens.
	bearerScheme = "Bearer"
	// BearerPrefix is the expected Authorization header prefix.
	BearerPrefix = bearerScheme + " "
)

// BearerTokenFromRequest extracts a bearer token from the Authorization header.
func BearerTokenFromRequest(req *restful.Request) (string, error) {
	authHeader := strings.TrimSpace(req.HeaderParameter(AuthorizationHeader))
	if authHeader == "" {
		return "", apierrors.NewUnauthorized("a Bearer token must be provided")
	}
	scheme, token, ok := strings.Cut(authHeader, " ")
	if !ok || !strings.EqualFold(scheme, bearerScheme) {
		return "", apierrors.NewUnauthorized("Authorization header must use Bearer authentication")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", apierrors.NewUnauthorized("a Bearer token must be provided")
	}
	return token, nil
}
