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

package client

import (
	"context"
	"time"

	kscheme "github.com/AlaudaDevops/pkg/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kerrors "github.com/AlaudaDevops/pkg/errors"

	"k8s.io/client-go/dynamic"
	"knative.dev/pkg/logging"

	apiserverrequest "k8s.io/apiserver/pkg/endpoints/request"

	"knative.dev/pkg/injection"

	"github.com/emicklei/go-restful/v3"
)

var (
	// k8s.io/apiserver/pkg/server/options/authorization.go
	allowCacheTTL = 10 * time.Second
	denyCacheTTL  = 10 * time.Second
)

// ImpersonateFilter will inject current user into context and inject impersonate information into rest.Config in request
func ImpersonateFilter(ctx context.Context) restful.FilterFunction {

	scheme := kscheme.Scheme(ctx)
	serviceAccountClient := Client(ctx)

	return func(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {

		reqCtx := request.Request.Context()
		log := logging.FromContext(reqCtx)

		user := ImpersonateUser(request.Request)
		if user == nil {
			chain.ProcessFilter(request, response)
			return
		}

		configInRequest := injection.GetConfig(reqCtx)

		// change config to impersonate config
		log.Debugw("impersonate user", "uid", user.GetUID(), "username",
			user.GetName(), "groups", user.GetGroups(), "extra", user.GetExtra())
		configInRequest.Impersonate.UID = user.GetUID()
		configInRequest.Impersonate.Groups = user.GetGroups()
		configInRequest.Impersonate.UserName = user.GetName()
		configInRequest.Impersonate.Extra = user.GetExtra()
		reqCtx = injection.WithConfig(reqCtx, configInRequest)
		reqCtx = apiserverrequest.WithUser(reqCtx, user)

		// overwrite direct client
		directClient, err := client.New(configInRequest, client.Options{Scheme: scheme, Mapper: serviceAccountClient.RESTMapper()})
		if err != nil {
			log.Debugw("impersonate filter direct client create error", "err", err)
			kerrors.HandleError(request, response, err)
			return
		}
		reqCtx = WithClient(reqCtx, directClient)

		// overwrite dynamic client
		dynamicClient, err := dynamic.NewForConfig(configInRequest)
		if err != nil {
			log.Errorw("error to create dynamic client", "err", err)
			kerrors.HandleError(request, response, err)
			return
		}
		reqCtx = WithDynamicClient(reqCtx, dynamicClient)

		request.Request = request.Request.WithContext(reqCtx)
		chain.ProcessFilter(request, response)
	}
}
