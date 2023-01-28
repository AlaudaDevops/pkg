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
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/golang-jwt/jwt"
)

const (

	// UserConfigName configuration/context for user
	UserConfigName = "UserConfig"
	// AuthorizationHeader authorization header for http requests
	AuthorizationHeader = "Authorization"
	// BearerPrefix bearer token prefix for token
	BearerPrefix = "Bearer "

	// QueryParameterTokenName authorization token for http requests
	QueryParameterTokenName = "token"
)

// FromBearerToken  retrieves config based on the bearer token
func FromBearerToken(req *restful.Request, baseConfig GetBaseConfigFunc) (config *rest.Config, err error) {
	if config, err = baseConfig(); err != nil {
		return
	}
	token := GetToken(req)
	if strings.TrimSpace(token) == "" {
		err = errors.NewUnauthorized("a Bearer token must be provided")
		return
	}
	cmd := BuildCmdConfig(&api.AuthInfo{Token: token}, config)
	config, err = cmd.ClientConfig()
	return
}

// ImpersonateConfig will make a impersonate config
func ImpersonateConfig(req *restful.Request, baseConfig GetBaseConfigFunc, saToken string) (config *rest.Config, err error) {

	// saTokenPath := "/run/secrets/kubernetes.io/serviceaccount/token"
	// saTokenBts, err := os.ReadFile(saTokenPath)
	// if err != nil {
	// return nil
	// }
	// saToken := string(saTokenBts)

	if config, err = baseConfig(); err != nil {
		return
	}

	token := GetToken(req)
	var user user.Info

	if strings.TrimSpace(token) != "" {
		user, err = userFromBearerToken(token)
		if err != nil {
			return nil, err
		}
	} else {
		user = impersonateUser(req.Request)
	}

	if user == nil {
		return nil, errors.NewUnauthorized("a Bearer token or impersonate user must be provided")
	}

	cmd := BuildCmdConfig(&api.AuthInfo{Token: saToken}, config)
	config, err = cmd.ClientConfig()

	config.Impersonate.UserName = user.GetName()
	config.Impersonate.Groups = user.GetGroups()
	config.Impersonate.UID = user.GetUID()
	config.Impersonate.Extra = user.GetExtra()

	return
}

func userFromBearerToken(rawToken string) (user.Info, error) {
	mapClaims := jwt.MapClaims{}

	// TODO: we should validate the signature
	_, _, err := new(jwt.Parser).ParseUnverified(rawToken, mapClaims)
	if err != nil {
		return nil, err
	}
	info := user.DefaultInfo{}
	// username is claim by email
	info.Name = mapClaims["email"].(string)
	info.Groups = mapClaims["groups"].([]string)

	return &info, nil
}

type claims map[string]json.RawMessage

func (c claims) unmarshalClaim(name string, v interface{}) error {
	val, ok := c[name]
	if !ok {
		return fmt.Errorf("claim not present")
	}
	return json.Unmarshal([]byte(val), v)
}

func (c claims) hasClaim(name string) bool {
	if _, ok := c[name]; !ok {
		return false
	}
	return true
}

// GetToken get token from request headers or request query parameters.
// return emtry if no token find
func GetToken(req *restful.Request) (token string) {
	authHeader := req.HeaderParameter(AuthorizationHeader)

	if authHeader != "" && strings.HasPrefix(authHeader, BearerPrefix) && strings.TrimPrefix(authHeader, BearerPrefix) != "" {
		token = strings.TrimPrefix(authHeader, BearerPrefix)
		return
	}

	token = req.QueryParameter(QueryParameterTokenName)
	return
}

func BuildCmdConfig(authInfo *api.AuthInfo, cfg *rest.Config) clientcmd.ClientConfig {
	cmdCfg := api.NewConfig()
	cmdCfg.Clusters[UserConfigName] = &api.Cluster{
		Server:                   cfg.Host,
		CertificateAuthority:     cfg.TLSClientConfig.CAFile,
		CertificateAuthorityData: cfg.TLSClientConfig.CAData,
		InsecureSkipTLSVerify:    cfg.TLSClientConfig.Insecure,
	}
	cmdCfg.AuthInfos[UserConfigName] = authInfo
	cmdCfg.Contexts[UserConfigName] = &api.Context{
		Cluster:  UserConfigName,
		AuthInfo: UserConfigName,
	}
	cmdCfg.CurrentContext = UserConfigName

	return clientcmd.NewDefaultClientConfig(
		*cmdCfg,
		&clientcmd.ConfigOverrides{},
	)
}
