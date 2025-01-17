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

package sharedmain

import (
	"context"

	"github.com/emicklei/go-restful/v3"
	"go.uber.org/zap"
)

type AddToRestContainer func(ws *restful.WebService)

// WebService is a basic interface that every web server should implement to create
// a new webservice and add into restful.container

type WebService interface {
	Name() string
	Setup(ctx context.Context, add AddToRestContainer, logger *zap.SugaredLogger) error
}
