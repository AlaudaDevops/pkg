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

package route

import (
	"context"
	"net/http"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
)

type healthz struct {
}

// NewHealthz basic health check service
func NewHealthz(ctx context.Context) Route {
	return &healthz{}
}

func (s *healthz) Register(ws *restful.WebService) {
	tags := []string{"system"}

	// ws.Consumes("*/*")
	ws.Route(
		ws.GET("/healthz").
			Doc("healthz").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			To(s.healthz))
	// TODO: make livez a more concrete check over the system?
	ws.Route(
		ws.GET("/livez").
			Doc("livez").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			To(s.healthz))
	ws.Route(
		ws.GET("/readyz").
			Doc("readyz").
			Metadata(restfulspec.KeyOpenAPITags, tags).
			To(s.healthz))
}

func (s *healthz) healthz(req *restful.Request, resp *restful.Response) {
	resp.WriteHeaderAndJson(http.StatusOK, map[string]string{"ok": "true"}, restful.MIME_JSON)
}
