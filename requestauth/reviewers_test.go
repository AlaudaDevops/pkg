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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// TestCurrentClusterTokenReviewerReviewToken verifies TokenReview request construction.
func TestCurrentClusterTokenReviewerReviewToken(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset()
	clientset.Fake.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authnv1.TokenReview)
		if review.Spec.Token != "request-token" {
			t.Fatalf("token = %q, want request-token", review.Spec.Token)
		}
		if got := fmt.Sprintf("%v", review.Spec.Audiences); got != "[kubernetes]" {
			t.Fatalf("audiences = %s, want [kubernetes]", got)
		}

		review.Status = authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: "dev",
				UID:      "uid-1",
				Groups:   []string{"system:authenticated"},
				Extra:    map[string]authnv1.ExtraValue{"scope": {"read"}},
			},
		}
		return true, review, nil
	})

	status, err := (&CurrentClusterTokenReviewer{Client: clientset}).ReviewToken(context.Background(), "request-token", []string{"kubernetes"})
	if err != nil {
		t.Fatalf("ReviewToken() error = %v", err)
	}
	if !status.Authenticated || status.User.Username != "dev" || status.User.Extra["scope"][0] != "read" {
		t.Fatalf("status = %#v, want authenticated dev", status)
	}
}

// TestCurrentClusterTokenReviewerReviewTokenErrors verifies TokenReview client errors.
func TestCurrentClusterTokenReviewerReviewTokenErrors(t *testing.T) {
	if _, err := (*CurrentClusterTokenReviewer)(nil).ReviewToken(context.Background(), "token", nil); err == nil {
		t.Fatalf("ReviewToken() nil receiver error = nil")
	}
	if _, err := (&CurrentClusterTokenReviewer{}).ReviewToken(context.Background(), "token", nil); err == nil {
		t.Fatalf("ReviewToken() nil client error = nil")
	}

	clientset := k8sfake.NewSimpleClientset()
	clientset.Fake.PrependReactor("create", "tokenreviews", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("token review failed")
	})
	if _, err := (&CurrentClusterTokenReviewer{Client: clientset}).ReviewToken(context.Background(), "token", nil); err == nil {
		t.Fatalf("ReviewToken() create error = nil")
	}
}

// TestTokenReviewExtraCopiesValues verifies authentication extra values are copied.
func TestTokenReviewExtraCopiesValues(t *testing.T) {
	if tokenReviewExtra(nil) != nil {
		t.Fatalf("empty extra conversion = non-nil")
	}

	source := map[string]authnv1.ExtraValue{"scope": {"read"}}
	converted := tokenReviewExtra(source)
	converted["scope"][0] = "write"
	if source["scope"][0] != "read" {
		t.Fatalf("source extra was mutated")
	}
}

// TestPlatformKubernetesReviewerReviewSelfSubject verifies platform SelfSubjectReview requests.
func TestPlatformKubernetesReviewerReviewSelfSubject(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/kubernetes/business/apis/authentication.k8s.io/v1/selfsubjectreviews" {
			http.NotFound(w, req)
			return
		}
		authorization = req.Header.Get("Authorization")
		writeJSON(t, w, map[string]any{
			"apiVersion": "authentication.k8s.io/v1",
			"kind":       "SelfSubjectReview",
			"status": map[string]any{
				"userInfo": map[string]any{
					"username": "platform-user",
					"uid":      "uid-1",
					"groups":   []string{"system:authenticated"},
				},
			},
		})
	}))
	defer server.Close()

	status, err := (&PlatformKubernetesReviewer{
		PlatformURL: server.URL + "/",
		ClusterName: "business",
	}).ReviewSelfSubject(context.Background(), " request-token ")
	if err != nil {
		t.Fatalf("ReviewSelfSubject() error = %v", err)
	}
	if status.UserInfo.Username != "platform-user" {
		t.Fatalf("username = %q, want platform-user", status.UserInfo.Username)
	}
	if authorization != "Bearer request-token" {
		t.Fatalf("authorization = %q, want bearer token", authorization)
	}
}

// TestPlatformKubernetesReviewerReviewSelfSubjectAccess verifies platform SSAR requests.
func TestPlatformKubernetesReviewerReviewSelfSubjectAccess(t *testing.T) {
	var review authv1.SelfSubjectAccessReview
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/kubernetes/business/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			http.NotFound(w, req)
			return
		}
		if err := json.NewDecoder(req.Body).Decode(&review); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		writeJSON(t, w, map[string]any{
			"apiVersion": "authorization.k8s.io/v1",
			"kind":       "SelfSubjectAccessReview",
			"status": map[string]any{
				"allowed": true,
				"reason":  "permitted",
			},
		})
	}))
	defer server.Close()

	status, err := (&PlatformKubernetesReviewer{
		PlatformURL: server.URL,
		ClusterName: "business",
	}).ReviewSelfSubjectAccess(context.Background(), "request-token", &AccessAttributes{
		ResourceAttributes: &authv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "get",
			Group:     "apps",
			Resource:  "deployments",
			Name:      "web",
		},
	})
	if err != nil {
		t.Fatalf("ReviewSelfSubjectAccess() error = %v", err)
	}
	if !status.Allowed || status.Reason != "permitted" {
		t.Fatalf("status = %#v, want allowed", status)
	}
	if review.Spec.ResourceAttributes == nil || review.Spec.ResourceAttributes.Resource != "deployments" {
		t.Fatalf("resource attributes = %#v, want deployments", review.Spec.ResourceAttributes)
	}
}

// TestPlatformKubernetesReviewerErrors verifies platform reviewer validation errors.
func TestPlatformKubernetesReviewerErrors(t *testing.T) {
	if _, err := NewPlatformKubernetesReviewer(Config{}, nil); err == nil {
		t.Fatalf("NewPlatformKubernetesReviewer() missing config error = nil")
	}

	insecure := false
	reviewer, err := NewPlatformKubernetesReviewer(Config{
		PlatformURL:                   "https://platform.example.com",
		ClusterName:                   "business",
		PlatformInsecureSkipTLSVerify: &insecure,
	}, nil)
	if err != nil {
		t.Fatalf("NewPlatformKubernetesReviewer() error = %v", err)
	}
	if reviewer.InsecureSkipTLSVerify {
		t.Fatalf("insecure TLS = true, want false")
	}

	if _, err := (*PlatformKubernetesReviewer)(nil).clientsetForToken("token"); err == nil {
		t.Fatalf("clientsetForToken() nil receiver error = nil")
	}
	if _, err := (&PlatformKubernetesReviewer{PlatformURL: "https://platform.example.com", ClusterName: "business"}).clientsetForToken(" "); !apierrors.IsUnauthorized(err) {
		t.Fatalf("clientsetForToken() empty token error = %v, want unauthorized", err)
	}
	if _, err := (&PlatformKubernetesReviewer{PlatformURL: "https://platform.example.com"}).clientsetForToken("token"); err == nil {
		t.Fatalf("clientsetForToken() missing cluster error = nil")
	}
	if _, err := reviewer.ReviewSelfSubjectAccess(context.Background(), "token", nil); err == nil {
		t.Fatalf("ReviewSelfSubjectAccess() nil attrs error = nil")
	}
}

// TestKubernetesSubjectAccessReviewerReview verifies SubjectAccessReview request construction.
func TestKubernetesSubjectAccessReviewerReview(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	var captured *authv1.SubjectAccessReview
	reviewer := &KubernetesSubjectAccessReviewer{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				review := obj.(*authv1.SubjectAccessReview)
				captured = review.DeepCopy()
				review.Status.Allowed = true
				return nil
			},
		}).Build(),
	}

	err := reviewer.Review(context.Background(), &user.DefaultInfo{
		Name:   "dev",
		UID:    "uid-1",
		Groups: []string{"team-a"},
		Extra:  map[string][]string{"scope": {"read"}},
	}, &AccessAttributes{
		ResourceAttributes: &authv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "update",
			Group:     "apps",
			Resource:  "deployments",
			Name:      "web",
		},
	})
	if err != nil {
		t.Fatalf("Review() error = %v", err)
	}
	if captured == nil {
		t.Fatalf("SubjectAccessReview was not created")
	}
	if captured.Spec.User != "dev" || captured.Spec.UID != "uid-1" || captured.Spec.Groups[0] != "team-a" {
		t.Fatalf("subject = %#v, want dev", captured.Spec)
	}
	if captured.Spec.Extra["scope"][0] != "read" {
		t.Fatalf("extra = %#v, want scope read", captured.Spec.Extra)
	}
	if captured.Spec.ResourceAttributes == nil || captured.Spec.ResourceAttributes.Name != "web" {
		t.Fatalf("resource attributes = %#v, want web deployment", captured.Spec.ResourceAttributes)
	}
}

// TestKubernetesSubjectAccessReviewerReviewDenied verifies denied SubjectAccessReview results.
func TestKubernetesSubjectAccessReviewerReviewDenied(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}

	reviewer := &KubernetesSubjectAccessReviewer{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				review := obj.(*authv1.SubjectAccessReview)
				review.Status.Allowed = false
				review.Status.Reason = "missing role"
				review.Status.EvaluationError = "rbac unavailable"
				return nil
			},
		}).Build(),
	}

	err := reviewer.Review(context.Background(), &user.DefaultInfo{Name: "dev"}, &AccessAttributes{
		NonResourceAttributes: &authv1.NonResourceAttributes{
			Path: "/apis",
			Verb: "get",
		},
	})
	if !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "missing role") || !strings.Contains(err.Error(), "rbac unavailable") {
		t.Fatalf("Review() error = %v, want forbidden with reason and evaluation error", err)
	}
}

// TestKubernetesSubjectAccessReviewerReviewErrors verifies validation and client errors.
func TestKubernetesSubjectAccessReviewerReviewErrors(t *testing.T) {
	if err := (*KubernetesSubjectAccessReviewer)(nil).Review(context.Background(), &user.DefaultInfo{Name: "dev"}, &AccessAttributes{NonResourceAttributes: &authv1.NonResourceAttributes{Path: "/", Verb: "get"}}); err == nil {
		t.Fatalf("Review() nil receiver error = nil")
	}

	reviewer := &KubernetesSubjectAccessReviewer{Client: fake.NewClientBuilder().Build()}
	if err := reviewer.Review(context.Background(), nil, &AccessAttributes{NonResourceAttributes: &authv1.NonResourceAttributes{Path: "/", Verb: "get"}}); !apierrors.IsUnauthorized(err) {
		t.Fatalf("Review() nil user error = %v, want unauthorized", err)
	}
	if err := reviewer.Review(context.Background(), &user.DefaultInfo{Name: "dev"}, nil); err == nil {
		t.Fatalf("Review() nil attrs error = nil")
	}

	scheme := runtime.NewScheme()
	if err := authv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}
	erroringReviewer := &KubernetesSubjectAccessReviewer{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return fmt.Errorf("create failed")
			},
		}).Build(),
	}
	if err := erroringReviewer.Review(context.Background(), &user.DefaultInfo{Name: "dev"}, &AccessAttributes{NonResourceAttributes: &authv1.NonResourceAttributes{Path: "/", Verb: "get"}}); err == nil {
		t.Fatalf("Review() create error = nil")
	}
}

// TestAuthzExtraCopiesValues verifies authorization extra values are copied.
func TestAuthzExtraCopiesValues(t *testing.T) {
	if authzExtra(nil) != nil {
		t.Fatalf("empty extra conversion = non-nil")
	}

	source := map[string][]string{"scope": {"read"}}
	converted := authzExtra(source)
	converted["scope"][0] = "write"
	if source["scope"][0] != "read" {
		t.Fatalf("source extra was mutated")
	}
}
