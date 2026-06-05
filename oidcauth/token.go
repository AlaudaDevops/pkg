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
	// BearerPrefix is the expected Authorization header prefix.
	BearerPrefix = "Bearer "
)

// BearerTokenFromRequest extracts a bearer token from the Authorization header.
func BearerTokenFromRequest(req *restful.Request) (string, error) {
	authHeader := req.HeaderParameter(AuthorizationHeader)
	if authHeader == "" {
		return "", apierrors.NewUnauthorized("a Bearer token must be provided")
	}
	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return "", apierrors.NewUnauthorized("Authorization header must use Bearer authentication")
	}

	token := strings.TrimSpace(strings.TrimPrefix(authHeader, BearerPrefix))
	if token == "" {
		return "", apierrors.NewUnauthorized("a Bearer token must be provided")
	}
	return token, nil
}
