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
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AccessAttributes stores Kubernetes authorization attributes.
type AccessAttributes struct {
	// ResourceAttributes describes a resource request.
	ResourceAttributes *authv1.ResourceAttributes
	// NonResourceAttributes describes a non-resource request.
	NonResourceAttributes *authv1.NonResourceAttributes
}

// AccessAttributesGetter returns authorization attributes for one request.
type AccessAttributesGetter interface {
	// GetAccessAttributes returns authorization attributes for one request.
	GetAccessAttributes(ctx context.Context, req *restful.Request) (*AccessAttributes, error)
}

// AccessAttributesGetterFunc adapts a function to AccessAttributesGetter.
type AccessAttributesGetterFunc func(ctx context.Context, req *restful.Request) (*AccessAttributes, error)

// GetAccessAttributes returns authorization attributes for one request.
func (f AccessAttributesGetterFunc) GetAccessAttributes(ctx context.Context, req *restful.Request) (*AccessAttributes, error) {
	return f(ctx, req)
}

// SubjectAccessReviewer checks Kubernetes authorization for an authenticated identity.
type SubjectAccessReviewer interface {
	// Review checks whether the user can perform the requested access.
	Review(ctx context.Context, user user.Info, attrs *AccessAttributes) error
}

// KubernetesSubjectAccessReviewer creates SubjectAccessReview resources.
// The component ServiceAccount must be allowed to create authorization.k8s.io
// SubjectAccessReview resources in the current cluster.
type KubernetesSubjectAccessReviewer struct {
	// Client creates SubjectAccessReview resources in the current cluster.
	Client client.Client
}

// Review checks Kubernetes authorization with SubjectAccessReview.
// It uses the configured client identity to create the review resource.
func (r *KubernetesSubjectAccessReviewer) Review(ctx context.Context, info user.Info, attrs *AccessAttributes) error {
	if r == nil || r.Client == nil {
		return fmt.Errorf("SubjectAccessReview client is nil")
	}
	if info == nil {
		return apierrors.NewUnauthorized("SubjectAccessReview user is nil")
	}
	if attrs == nil || (attrs.ResourceAttributes == nil && attrs.NonResourceAttributes == nil) {
		return fmt.Errorf("SubjectAccessReview attributes are nil")
	}

	review := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			User:                  info.GetName(),
			Groups:                append([]string{}, info.GetGroups()...),
			UID:                   info.GetUID(),
			Extra:                 authzExtra(info.GetExtra()),
			ResourceAttributes:    attrs.ResourceAttributes,
			NonResourceAttributes: attrs.NonResourceAttributes,
		},
	}
	if err := r.Client.Create(ctx, review); err != nil {
		return fmt.Errorf("failed to create SubjectAccessReview: %w", err)
	}
	if review.Status.Allowed {
		return nil
	}

	resource := schema.GroupResource{Group: "authorization.k8s.io", Resource: "subjectaccessreviews"}
	name := ""
	verb := ""
	if attrs.ResourceAttributes != nil {
		resource = schema.GroupResource{
			Group:    attrs.ResourceAttributes.Group,
			Resource: attrs.ResourceAttributes.Resource,
		}
		name = attrs.ResourceAttributes.Name
		verb = attrs.ResourceAttributes.Verb
	}
	if attrs.NonResourceAttributes != nil {
		name = attrs.NonResourceAttributes.Path
		verb = attrs.NonResourceAttributes.Verb
	}

	message := fmt.Sprintf("access not allowed, verb=%s", verb)
	if review.Status.EvaluationError != "" {
		message = fmt.Sprintf("%s, evaluationError=%s", message, review.Status.EvaluationError)
	}
	if review.Status.Reason != "" {
		message = fmt.Sprintf("%s, reason=%s", message, review.Status.Reason)
	}
	return apierrors.NewForbidden(resource, name, fmt.Errorf("%s", message))
}

// NewSubjectAccessReviewFilter returns a filter that authenticates and authorizes by SAR.
// The component ServiceAccount must be allowed to create authorization.k8s.io
// SubjectAccessReview resources. If the authenticator uses Kubernetes TokenReview fallback,
// it must also be allowed to create authentication.k8s.io TokenReview resources.
func NewSubjectAccessReviewFilter(authenticator TokenAuthenticator, reviewer SubjectAccessReviewer, getter AccessAttributesGetter) restful.FilterFunction {
	authnFilter := NewAuthenticationFilter(authenticator)
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		authnFilter(req, resp, &restful.FilterChain{
			Target: func(authenticatedReq *restful.Request, authenticatedResp *restful.Response) {
				result := AuthenticationResultFromContext(authenticatedReq.Request.Context())
				if result == nil || result.User == nil {
					kerrors.HandleError(authenticatedReq, authenticatedResp, apierrors.NewUnauthorized("request authentication did not return a user"))
					return
				}
				if reviewer == nil {
					kerrors.HandleError(authenticatedReq, authenticatedResp, fmt.Errorf("SubjectAccessReviewer is nil"))
					return
				}
				if getter == nil {
					kerrors.HandleError(authenticatedReq, authenticatedResp, fmt.Errorf("AccessAttributesGetter is nil"))
					return
				}

				attrs, err := getter.GetAccessAttributes(authenticatedReq.Request.Context(), authenticatedReq)
				if err != nil {
					kerrors.HandleError(authenticatedReq, authenticatedResp, err)
					return
				}
				if err := reviewer.Review(authenticatedReq.Request.Context(), result.User, attrs); err != nil {
					kerrors.HandleError(authenticatedReq, authenticatedResp, err)
					return
				}
				chain.ProcessFilter(authenticatedReq, authenticatedResp)
			},
		})
	}
}

// authzExtra converts apiserver user extra values to authorization.k8s.io extra values.
func authzExtra(extra map[string][]string) map[string]authv1.ExtraValue {
	if len(extra) == 0 {
		return nil
	}
	result := map[string]authv1.ExtraValue{}
	for key, values := range extra {
		result[key] = authv1.ExtraValue(append([]string{}, values...))
	}
	return result
}
