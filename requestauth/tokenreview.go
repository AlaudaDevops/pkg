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

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// TokenReviewer validates a bearer token through Kubernetes TokenReview.
type TokenReviewer interface {
	// ReviewToken returns the TokenReview status for a bearer token.
	ReviewToken(ctx context.Context, token string, audiences []string) (*authnv1.TokenReviewStatus, error)
}

// CurrentClusterTokenReviewer creates TokenReview requests against the current cluster.
type CurrentClusterTokenReviewer struct {
	// Client is the Kubernetes clientset used for TokenReview.
	Client kubernetes.Interface
}

// NewCurrentClusterTokenReviewer builds a TokenReview client from a REST config.
func NewCurrentClusterTokenReviewer(config *rest.Config) (*CurrentClusterTokenReviewer, error) {
	if config == nil {
		return nil, fmt.Errorf("Kubernetes REST config is nil")
	}
	clientset, err := kubernetes.NewForConfig(rest.CopyConfig(config))
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}
	return &CurrentClusterTokenReviewer{Client: clientset}, nil
}

// ReviewToken creates a Kubernetes TokenReview.
func (r *CurrentClusterTokenReviewer) ReviewToken(ctx context.Context, token string, audiences []string) (*authnv1.TokenReviewStatus, error) {
	if r == nil || r.Client == nil {
		return nil, fmt.Errorf("Kubernetes TokenReview client is nil")
	}

	review := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: append([]string{}, audiences...),
		},
	}
	review, err := r.Client.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create TokenReview: %w", err)
	}
	return &review.Status, nil
}

// tokenReviewExtra converts authentication.k8s.io extra values to apiserver user extra values.
func tokenReviewExtra(extra map[string]authnv1.ExtraValue) map[string][]string {
	if len(extra) == 0 {
		return nil
	}
	result := map[string][]string{}
	for key, values := range extra {
		result[key] = append([]string{}, values...)
	}
	return result
}
