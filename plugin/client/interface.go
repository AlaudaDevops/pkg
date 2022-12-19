/*
Copyright 2021 The Katanomi Authors.

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

package client

import (
	"context"

	metav1alpha1 "github.com/katanomi/pkg/apis/meta/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"

	"go.uber.org/zap"
)

// Interface base interface for plugins
type Interface interface {
	Path() string
	Setup(context.Context, *zap.SugaredLogger) error
}

// PluginRegister plugin registration methods to update IntegrationClass status
type PluginRegister interface {
	Interface
	GetIntegrationClassName() string
	// GetAddressURL Returns its own plugin access URL
	GetAddressURL() *apis.URL
	// GetWebhookURL Returns a Webhook accessible URL for external tools
	// If not supported return nil, false
	GetWebhookURL() (*apis.URL, bool)
	// GetSupportedVersions Returns a list of supported versions by the plugin
	// For SaaS platform plugins use a "online" version.
	GetSupportedVersions() []string
	// GetSecretTypes Returns all secret types supported by the plugin
	GetSecretTypes() []string
	// GetReplicationPolicyTypes return replication policy types for ClusterIntegration
	GetReplicationPolicyTypes() []string
	// GetResourceTypes Returns a list of Resource types that can be used in ClusterIntegration and Integration
	GetResourceTypes() []string
	// GetAllowEmptySecret Returns if an empty secret is allowed with IntegrationClass
	GetAllowEmptySecret() []string
}

// ResourcePathFormatter implements a formatter for resource path base on different scene
type ResourcePathFormatter interface {
	// GetResourcePathFmt resource path format
	GetResourcePathFmt() map[metav1alpha1.ResourcePathScene]string
	// GetSubResourcePathFmt resource path format
	GetSubResourcePathFmt() map[metav1alpha1.ResourcePathScene]string
}

// AuthChecker implements an authorization check method for plugins
type AuthChecker interface {
	AuthCheck(ctx context.Context, option metav1alpha1.AuthCheckOptions) (*metav1alpha1.AuthCheck, error)
}

// AuthTokenGenerator implements token generation/refresh API method
type AuthTokenGenerator interface {
	AuthToken(ctx context.Context) (*metav1alpha1.AuthToken, error)
}

type PluginAttributes interface {
	SetAttribute(k string, values ...string)
	GetAttribute(k string) []string
	Attributes() map[string][]string
}

// Client inteface for PluginClient, client code shoud use the interface
// as dependency
type Client interface {
	Get(ctx context.Context, baseURL *duckv1.Addressable, uri string, options ...OptionFunc) error
	Post(ctx context.Context, baseURL *duckv1.Addressable, uri string, options ...OptionFunc) error
	Put(ctx context.Context, baseURL *duckv1.Addressable, uri string, options ...OptionFunc) error
	Delete(ctx context.Context, baseURL *duckv1.Addressable, uri string, options ...OptionFunc) error
}

type ClientProjectGetter interface {
	Project(meta Meta, secret corev1.Secret) ClientProject
}

// LivenessChecker check the tool service is alive
type LivenessChecker interface {
	// CheckAlive check the tool service is alive
	CheckAlive(ctx context.Context) error
}

// Initializer initialize the tool service
type Initializer interface {
	// Initialize  the tool service if desired
	Initialize(ctx context.Context) error
}
