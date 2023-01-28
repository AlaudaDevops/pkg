package client

import (
	"context"
	"net/http"
	"time"

	"knative.dev/pkg/logging"

	"k8s.io/apimachinery/pkg/runtime"

	"knative.dev/pkg/injection"

	apiserverfilters "k8s.io/apiserver/pkg/endpoints/filters"
	apiserverwebhook "k8s.io/apiserver/plugin/pkg/authorizer/webhook"

	"github.com/emicklei/go-restful/v3"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
)

// filter 执行顺序
// manager filter: 根据request 初始化 client
// impersonate filter: 校验当前用户是否有权限执行impersonate， 当前 req context client 为 request user client, 同时 将client 修改为 impersonate client
// rbac filter: SubjectReview: 传递了 impersonate header， 则 使用  impersonate client， 创建 subject review
//                               未传递 impersonate header,则 使用 request client， 创建 self subject review

var (
	// k8s.io/apiserver/pkg/server/options/authorization.go
	allowCacheTTL = 10 * time.Second
	denyCacheTTL  = 10 * time.Second
)

func ImpersonateFilter(ctx context.Context, s runtime.NegotiatedSerializer) (restful.FilterFunction, error) {

	config := injection.GetConfig(ctx)
	log := logging.FromContext(ctx)

	webhookAuthorizer, err := apiserverwebhook.New(config, "v1", allowCacheTTL, denyCacheTTL, *apiserveroptions.DefaultAuthWebhookRetryBackoff())
	if err != nil {
		log.Errorw("error to new WebhookAuthorizer", "error", err)
		return nil, err
	}

	return func(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {

		reqCtx := request.Request.Context()
		log.Infof("======> debug: in impersonate filter")

		chainHandler := filterChainAsHttpHandler(request, response, chain)

		user := impersonateUser(request.Request)
		if user == nil {
			chain.ProcessFilter(request, response)
			return
		}

		reqConfig := injection.GetConfig(reqCtx)

		// change config to impersonate config
		reqConfig.Impersonate.UID = user.GetUID()
		reqConfig.Impersonate.Groups = user.GetGroups()
		reqConfig.Impersonate.UserName = user.GetName()
		reqConfig.Impersonate.Extra = user.GetExtra()

		reqCtx = injection.WithConfig(reqCtx, reqConfig)
		request.Request = request.Request.WithContext(reqCtx)

		log.Infof("======> debug: inside impersonate filter")
		apiserverfilters.WithImpersonation(chainHandler, webhookAuthorizer, s)
		request.Request = request.Request.WithContext(WithUser(ctx, user))
		log.Infof("======> debug: outside impersonate filter: %s", User(request.Request.Context()))
		chain.ProcessFilter(request, response)
	}, nil
}

func filterChainAsHttpHandler(request *restful.Request, response *restful.Response, chain *restful.FilterChain) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		chain.ProcessFilter(request, response)
	})
}
