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

package admission

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/AlaudaDevops/pkg/sharedmain"
	"knative.dev/pkg/logging"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type DefaulterWebhook interface {
	Defaulter
	sharedmain.WebhookSetup
	sharedmain.WebhookRegisterSetup
	WithTransformer(transformers ...TransformFunc) DefaulterWebhook
	WithLoggerName(loggerName string) DefaulterWebhook
}

type defaulterWebhook struct {
	Defaulter
	LoggerName   string
	transformers []TransformFunc
}

func (d *defaulterWebhook) WithLoggerName(loggerName string) DefaulterWebhook {
	d.LoggerName = loggerName
	return d
}

func (d *defaulterWebhook) WithTransformer(transformers ...TransformFunc) DefaulterWebhook {
	d.transformers = transformers

	return d
}

func NewDefaulterWebhook(defaulter Defaulter) DefaulterWebhook {
	return &defaulterWebhook{
		Defaulter: defaulter,
	}
}

func (d *defaulterWebhook) GetLoggerName() string {
	if d.LoggerName != "" {
		return d.LoggerName
	}
	if d.Defaulter != nil {
		typeName := strings.ToLower(reflect.TypeOf(d.Defaulter).Name())

		return fmt.Sprintf("%s-webhook-transformer", typeName)
	}

	return "webhook-transformer"
}

func (r *defaulterWebhook) SetupWebhookWithManager(mgr ctrl.Manager) error {
	_, implementsValidator := r.Defaulter.(admission.Validator)
	if !implementsValidator {
		// not necessary to run this part if not implemented
		return nil
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(r.Defaulter).
		Complete()
}

func (d *defaulterWebhook) SetupRegisterWithManager(ctx context.Context, mgr ctrl.Manager) {
	log := logging.FromContext(ctx)

	if d.Defaulter == nil {
		log.Fatalw("webhook defaulter required")
		return
	}

	err := RegisterDefaultWebhookFor(ctx, mgr, d.Defaulter, d.transformers...)
	if err != nil {
		log.Fatalw("register webhook failed", "err", err)
	}
}
