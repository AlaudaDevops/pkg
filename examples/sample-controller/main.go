/*
Copyright 2021 The AlaudaDevops Authors.

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

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/logging"

	"github.com/AlaudaDevops/pkg/sharedmain"
	"github.com/AlaudaDevops/pkg/webhook/admission"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	testv1alpha1 "github.com/AlaudaDevops/pkg/examples/sample-controller/apis/test/v1alpha1"
	testcontrollers "github.com/AlaudaDevops/pkg/examples/sample-controller/controllers/test"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"knative.dev/pkg/apis"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(testv1alpha1.AddToScheme(scheme))
}

func main() {

	sharedmain.App("controller").
		Scheme(scheme).
		// Overrides a MultiClusterClient
		// by default will load the multicluster.ClusterRegistryClient
		// MultiClusterClient(Interface).
		Log().
		Profiling().
		Controllers(
			&testcontrollers.FooBarReconciler{},
			// &Controller{},
			// &Controller2{},
		).
		Webhooks(
			// custom default webhook
			admission.NewDefaulterWebhook(&testv1alpha1.FooBar{}).WithTransformer(
				WithCreateUpdateTimes(),
			).WithLoggerName("foobar-defaulting"),
			// custom validation webhook
			admission.NewValidatorWebhook(&testv1alpha1.FooBar{}).
				WithValidateCreate(ValidateNameToHaveABC()).WithLoggerName("foobar-validating"),
		).
		APIDocs().
		Run()
}

// ValidateNameToHaveABC extended create validation function added here
func ValidateNameToHaveABC() admission.ValidateCreateFunc {
	return func(ctx context.Context, obj runtime.Object, req ctrladmission.Request) error {
		metaobj, ok := obj.(metav1.Object)
		if !ok {
			return fmt.Errorf("invalid object?")
		}

		if !strings.Contains(metaobj.GetName(), "abc") {
			return fmt.Errorf("metadata.name should contain \"abc\"")
		}
		return nil
	}
}

// WithCreateUpdateTimes extended defaulting/transformation function added here
func WithCreateUpdateTimes() admission.TransformFunc {
	return func(ctx context.Context, obj runtime.Object, req ctrladmission.Request) {
		metaobj, ok := obj.(metav1.Object)
		if !ok {
			return
		}
		log := logging.FromContext(ctx).With("name", metaobj.GetName(), "ns", metaobj.GetNamespace())
		annotations := metaobj.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}

		now := time.Now().Format(time.RFC3339)
		if apis.IsInCreate(ctx) {
			log.Debugw("adding created time", "time", now)
			annotations["createdAt"] = now
		} else if apis.IsInUpdate(ctx) {
			annotations["updatedAt"] = now
			log.Debugw("adding updated time", "time", now)
		} else {
			// not changed
		}
		metaobj.SetAnnotations(annotations)
	}
}

type Controller struct {
	*zap.SugaredLogger

	ctrlclient.Client
}

func (c *Controller) Name() string {
	return "controller-test"
}

func (c *Controller) Setup(ctx context.Context, mgr manager.Manager, logger *zap.SugaredLogger) error {
	logger.Debugw("setup.debug", "ctrl", c.Name())
	logger.Infow("setup.info", "ctrl", c.Name())
	logger.Warnw("setup.warn", "ctrl", c.Name())
	logger.Errorw("setup.error", "ctrl", c.Name())
	c.SugaredLogger = logger
	c.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(c)
}

// CheckSetup make possible to lazy load controllers when dependencies are not installed yet
// in this example a simple list secrets is used to check
func (c *Controller) CheckSetup(ctx context.Context, mgr manager.Manager, _ *zap.SugaredLogger) error {
	return mgr.GetClient().List(ctx, &corev1.SecretList{})
}

func (c *Controller) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := c.With("key", req)

	obj := &corev1.ConfigMap{}
	if err = c.Get(ctx, req.NamespacedName, obj); err != nil {
		log.Errorw("error getting configmap", "err", err)
		err = nil // no point in retrying
		return
	}

	log.Infow("got configmap", "len(data)", len(obj.Data))
	log.Debugw("configmap data", "data", obj.Data)
	return
}

type Controller2 struct {
	ctrlclient.Client
	*zap.SugaredLogger
}

func (c *Controller2) Name() string {
	return "controller-test-bak"
}

func (c *Controller2) Setup(ctx context.Context, mgr manager.Manager, logger *zap.SugaredLogger) error {
	logger.Debugw("setup.debug", "ctrl", c.Name())
	logger.Infow("setup.info", "ctrl", c.Name())
	logger.Warnw("setup.warn", "ctrl", c.Name())
	logger.Errorw("setup.error", "ctrl", c.Name())
	c.Client = mgr.GetClient()
	c.SugaredLogger = logger

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(c)
}

// CheckSetup does nothing so just return nil
func (c *Controller2) CheckSetup(ctx context.Context, mgr manager.Manager, _ *zap.SugaredLogger) error {
	return nil
}

func (c *Controller2) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := c.With("key", req)

	obj := &corev1.Secret{}
	if err = c.Get(ctx, req.NamespacedName, obj); err != nil {
		log.Errorw("error getting secret", "err", err)
		err = nil // no point in retrying
		return
	}

	log.Infow("got secret", "len(data)", len(obj.Data), "type", obj.Type)
	log.Debugw("secret data", "data", obj.Data)
	return
}
