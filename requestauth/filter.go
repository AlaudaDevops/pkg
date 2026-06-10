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

// NewAuthenticationFilter returns a go-restful filter that authenticates Bearer
// token requests and stores the authenticated user in the request context.
//
// With the built-in Authenticator, authentication is attempted in this order:
//
//   - Platform SelfSubjectReview against
//     {platformURL}/kubernetes/{clusterName}, using the original request token.
//     This proves that the platform-routed Kubernetes API accepts the token and
//     returns the userInfo seen by that API. The component ServiceAccount does
//     not need TokenReview permission for this backend; the token user must be
//     allowed to create selfsubjectreviews.authentication.k8s.io on the
//     platform-routed API.
//   - Explicitly enabled OIDC verification through discovery and JWKS. This
//     backend does not call Kubernetes for authentication, so it requires no
//     Kubernetes RBAC permission for authentication-only filters.
//   - Current-cluster TokenReview. The component ServiceAccount must be allowed
//     to create tokenreviews.authentication.k8s.io in the current cluster.
//
// The filter never creates SelfSubjectAccessReview or SubjectAccessReview. Use
// NewSubjectAccessReviewFilter when a route needs resource or non-resource
// authorization in addition to authentication.
func NewAuthenticationFilter(authenticator TokenAuthenticator) restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		if authenticator == nil {
			kerrors.HandleError(req, resp, fmt.Errorf("request authenticator is nil"))
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

		processAuthenticatedRequest(req, resp, chain, result)
	}
}

// processAuthenticatedRequest stores authentication data and continues the filter chain.
func processAuthenticatedRequest(req *restful.Request, resp *restful.Response, chain *restful.FilterChain, result *AuthenticationResult) {
	if result == nil || result.User == nil {
		kerrors.HandleError(req, resp, apierrors.NewUnauthorized("request authentication did not return a user"))
		return
	}

	reqCtx := apiserverrequest.WithUser(req.Request.Context(), result.User)
	reqCtx = WithAuthenticationResult(reqCtx, result)
	req.Request = req.Request.WithContext(reqCtx)
	chain.ProcessFilter(req, resp)
}
