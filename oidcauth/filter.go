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

	kerrors "github.com/AlaudaDevops/pkg/errors"
	"github.com/emicklei/go-restful/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiserverrequest "k8s.io/apiserver/pkg/endpoints/request"
	"knative.dev/pkg/logging"
)

// authenticationResultContextKey stores the authentication result in request contexts.
type authenticationResultContextKey struct{}

// WithAuthenticationResult stores an AuthenticationResult in a context.
func WithAuthenticationResult(ctx context.Context, result *AuthenticationResult) context.Context {
	return context.WithValue(ctx, authenticationResultContextKey{}, result)
}

// AuthenticationResultFromContext retrieves an AuthenticationResult from a context.
func AuthenticationResultFromContext(ctx context.Context) *AuthenticationResult {
	result, _ := ctx.Value(authenticationResultContextKey{}).(*AuthenticationResult)
	return result
}

// NewAuthenticationFilter returns a go-restful filter that authenticates Bearer tokens only.
// When the authenticator uses current-cluster Kubernetes fallback, the component ServiceAccount
// must be allowed to create authentication.k8s.io TokenReview resources.
func NewAuthenticationFilter(authenticator TokenAuthenticator) restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		if authenticator == nil {
			kerrors.HandleError(req, resp, fmt.Errorf("OIDC authenticator is nil"))
			return
		}

		rawToken, err := BearerTokenFromRequest(req)
		if err != nil {
			kerrors.HandleError(req, resp, err)
			return
		}

		result, err := authenticator.Authenticate(req.Request.Context(), rawToken)
		if err != nil {
			logging.FromContext(req.Request.Context()).Debugw("request authentication failed", "error", err)
			kerrors.HandleError(req, resp, err)
			return
		}
		if result == nil || result.User == nil {
			kerrors.HandleError(req, resp, apierrors.NewUnauthorized("request authentication did not return a user"))
			return
		}

		reqCtx := apiserverrequest.WithUser(req.Request.Context(), result.User)
		reqCtx = WithAuthenticationResult(reqCtx, result)
		req.Request = req.Request.WithContext(reqCtx)
		chain.ProcessFilter(req, resp)
	}
}
