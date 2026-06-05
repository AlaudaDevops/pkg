# OIDC 认证与 Kubernetes RBAC 鉴权机制分析

## 结论摘要

本次目标是在 `github.com/AlaudaDevops/pkg` 这个共享仓库中沉淀一套可复用的认证/鉴权机制，供 Connectors API 以及其他组件复用。推荐的核心链路是：

1. 组件从 HTTP 请求中提取 Bearer token。
2. 组件按配置的 OIDC issuer 做 discovery，获取 JWKS 地址和 issuer 元数据。
3. 组件自行校验 OIDC token 的签名、`iss`、`aud`、`exp`、`nbf`、`iat` 等字段。
4. 组件把可信 claims 映射成 Kubernetes authorizer 可识别的 `user` 和 `groups` 字符串。
5. 组件使用自己的 ServiceAccount 在当前业务集群创建 `SubjectAccessReview`。
6. 当前集群 Kubernetes RBAC 根据 SAR 中的 `user/groups/resourceAttributes` 返回允许或拒绝。

这条链路把两个问题拆开处理：

- 认证：token 是否由可信 OIDC issuer 签发，是否签给当前组件或当前 client，是否仍有效。
- 鉴权：映射出来的 Kubernetes 身份在当前集群是否具备访问目标资源的 RBAC 权限。

这比直接把 OIDC token 交给当前业务集群 kube-apiserver 更通用。真实环境验证显示，业务集群 direct API 不一定信任平台 OIDC id_token，因此不能把 `SelfSubjectAccessReview` 作为通用方案。

## 真实环境验证结论

验证日期：2026-06-05。

验证环境：

- global 集群 kubeconfig：`/root/config/global`
- 业务集群 kubeconfig：`/root/config/yzc`
- 登录入口：`https://devops-daily-eleqy7--idp.alaudatech.net/`

以下只记录认证/鉴权机制相关结论，不记录 token、client secret、密码或会话 cookie。

### global-info 与默认配置来源

`global` 和 `yzc` 两个集群的 `kube-public/global-info` 都包含 OIDC 相关字段：

- `oidcIssuer`: `https://devops-daily-eleqy7--idp.alaudatech.net/dex`
- `oidcClientID`: `alauda-auth`
- `oidcClientSecretRef`: `cpaas-oidc-secret`
- `oidcResponseType`: `code`
- `oidcScopes`: 包含 `openid`、`profile`、`email`、`groups` 等信息

需要注意：

- `global-info.data.oidcClientSecret` 在该环境中为空。
- 实际 client secret 存在 `cpaas-system/cpaas-oidc-secret` Secret 中，字段为 `client-secret`。
- `global-info` 能作为 ACP 默认发现机制，但不应作为公共库强依赖。共享库必须支持外部直接传入 issuer、audience、client ID、CA、claims 映射规则等配置。

### OIDC discovery 与 JWKS

对 `oidcIssuer + "/.well-known/openid-configuration"` 做 discovery，验证到：

- `issuer`: `https://devops-daily-eleqy7--idp.alaudatech.net/dex`
- `authorization_endpoint`: 平台包装后的 `/console-dex/auth`
- `token_endpoint`: `/dex/token`
- `jwks_uri`: `/dex/keys`
- `id_token_signing_alg_values_supported`: `RS256`
- `code_challenge_methods_supported`: `S256` 和 `plain`

JWKS 中存在多把 RSA 公钥，`use=sig`，`alg=RS256`。OIDC token header 中的 `kid` 可以在 JWKS 中找到匹配公钥，并用于验签。

### 登录与 token 获取链路

当前平台不是直接暴露 Dex 默认登录表单，而是通过 `console-dex` SPA 和平台包装 API 完成登录：

- 前端调用 `/dex/api/v1/authorize` 创建认证请求。
- 当前 client 要求 PKCE，缺少 `code_challenge` 会返回 `PKCE code_challenge is required for this client`。
- 本地账号登录调用 `/dex/api/v1/authorize/local?req=...`。
- 登录密码在前端用 `/dex/pubkey` 返回的 RSA 公钥加密后提交。
- 登录成功后返回 `console-auth/callback?code=...&state=...`。
- 调用 `/dex/token` 换 token 时，该环境接受表单中的 `client_id` 和 `client_secret`，不接受 HTTP Basic client authentication。

这些属于当前 ACP 平台登录实现细节，不属于 OIDC 通用验证逻辑。共享库不应把 `/dex/api/v1`、`/dex/pubkey`、`console-auth` 等路径内置为认证依赖。组件服务端只需要验证请求中已有的 Bearer token。

### id_token claims 形态

通过真实登录获取并验签 id_token，关键 claims 如下：

```json
{
  "iss": "https://devops-daily-eleqy7--idp.alaudatech.net/dex",
  "aud": "alauda-auth",
  "email": "admin@cpaas.io",
  "email_verified": true,
  "preferred_username": "admin@cpaas.io",
  "name": "admin",
  "groups": null,
  "roles": [
    "platform-admin-system"
  ]
}
```

结论：

- `preferred_username` 和 `email` 在该环境中都能表示当前用户，且值为 `admin@cpaas.io`。
- token 中没有标准 `groups` claim。
- token 中有平台角色 `roles=["platform-admin-system"]`。
- `roles` 是当前平台的角色 claim，不是 Kubernetes `Role` 资源，也不是 OIDC 必然存在的标准组字段。

因此，默认把 `preferred_username` fallback 到 `email` 是为了兼容当前 ACP RBAC 绑定，不是 OIDC 通用安全默认。更通用、更稳定的身份字段通常是 `sub`，但当前集群现有 RBAC 没有按 `sub` 绑定。

### direct API、平台代理 API 与 OIDC token

用真实 id_token 分别访问业务集群 direct API 和平台代理 API，验证到：

- 业务集群 direct API：拒绝该 OIDC id_token，返回未认证。
- 平台代理 API `/kubernetes/zcyu`：接受该 id_token，并把用户识别为 `admin@cpaas.io`，groups 中只有 `system:authenticated`。

这说明现有 connectors 逻辑中通过 `platformURL + "/kubernetes/" + clusterName` 使用 Erebus/平台代理做权限检查，在 ACP 环境下成立；但这不是普通 Kubernetes 集群的通用机制。

也验证到 kubeconfig 中的 token 不是 OIDC 用户 token，而是 Kubernetes ServiceAccount token：

- `iss`: `https://kubernetes.default.svc.cluster.local`
- `sub`: `system:serviceaccount:cpaas-system:kubeconfig`

实现时不能只看到 JWT 格式就按 OIDC 用户 token 处理，必须校验 issuer 和 audience。

### 当前集群 RBAC 对映射身份的结果

在业务集群 direct API 中，用管理员 kubeconfig 发起 `SubjectAccessReview` 语义验证：

- `--as=admin@cpaas.io` 可以命中当前集群 RBAC。
- `--as=admin@cpaas.io --as-group=platform-admin-system` 也可以命中。
- `--as=<id_token.sub>` 不能命中。

这说明推荐链路中，将 claims 映射为 `user=admin@cpaas.io` 后，当前集群 RBAC 可以完成鉴权，即使 direct kube-apiserver 本身不接受原始 OIDC id_token。

### connectors 当前 RBAC 差距

当前 `connectors-api-role` 具备读取 `connectors`、`connectorclasses`、`secrets`、`configmaps` 等权限，也具备 `connectors/proxy` 权限，但不具备创建 `subjectaccessreviews.authorization.k8s.io` 的权限。

新 OIDC SAR 路径需要 Connectors API 或复用该机制的组件 ServiceAccount 具备：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: oidc-subjectaccessreviewer
rules:
  - apiGroups:
      - authorization.k8s.io
    resources:
      - subjectaccessreviews
    verbs:
      - create
```

该权限只允许组件询问 authorizer 某个身份是否具备某项权限，不直接授予被查询用户业务资源权限。

## OIDC 通用概念说明

### OIDC issuer

OIDC issuer 是 token 签发方的唯一标识，通常是一个 HTTPS URL。服务端必须配置预期 issuer，并校验 token 中的 `iss` 与配置完全一致。

如果不校验 issuer，攻击者可能拿另一个身份系统签发的 token 访问当前组件。即使 token 本身签名合法，也不是当前组件信任的签发方。

### Discovery

OIDC discovery 是标准元数据发现机制。服务端通常访问：

```text
{issuer}/.well-known/openid-configuration
```

返回内容中最重要的是：

- `issuer`: 需要与配置值一致。
- `jwks_uri`: 用于下载验签公钥。
- `id_token_signing_alg_values_supported`: 支持的签名算法。
- `authorization_endpoint`、`token_endpoint`: 登录和换 token 用端点，组件作为资源服务器时通常不需要直接参与。

共享库应通过 discovery 自动发现 JWKS，不应要求调用方硬编码 JWKS 地址。

### JWKS 与签名校验

JWKS 是 JSON Web Key Set，即 issuer 对外暴露的一组公钥。OIDC id_token 通常是 JWT：

```text
base64url(header).base64url(payload).base64url(signature)
```

header 中的 `kid` 表示使用哪把 key 签名。验证流程：

1. 读取 token header 中的 `kid` 和 `alg`。
2. 从 issuer JWKS 中找到相同 `kid` 的公钥。
3. 用该公钥和声明的算法验证 JWT signature。
4. 验签失败时拒绝请求。

JWKS 需要缓存，但必须支持 key rotation。当 `kid` 找不到或验签失败时，可以刷新 JWKS 后重试一次，避免 issuer 轮换密钥导致短暂失败。

### Audience

`aud` 表示 token 的目标接收方。服务端必须校验 `aud` 包含当前配置的 audience，通常是 OIDC client ID。

如果不校验 audience，签给其他系统的 token 可能被拿来访问当前组件，形成 confused deputy 问题。

当前环境中 id_token 的 `aud` 是 `alauda-auth`，与 `oidcClientID` 一致。

### 时间字段

服务端至少需要校验：

- `exp`: 过期时间。当前时间晚于 `exp` 必须拒绝。
- `nbf`: not before。当前时间早于 `nbf` 必须拒绝；该字段可能不存在。
- `iat`: issued at。可用于拒绝签发时间明显在未来的 token，也可配合最大 token 年龄策略使用。

实现应支持少量 clock skew，例如 1 到 2 分钟，但默认不要无限放宽。

### ID Token 与 Access Token

OIDC 中常见两类 token：

- ID token：向客户端证明用户身份，包含 `sub`、`email`、`preferred_username` 等身份 claims。
- Access token：用于访问资源服务。不同 issuer 对 access token 的格式和 claims 不完全一致。

当前环境中 id_token 和 access_token 都是 RS256 JWT，claims 形态基本一致。但通用实现不应假设所有 issuer 的 access token 都是可本地验签 JWT。建议 v1 明确支持校验 OIDC JWT bearer token，并允许调用方指定接受 id_token、access_token 或两者。

## Kubernetes 鉴权概念说明

### User、Group、Role 与 RoleBinding

Kubernetes authorizer 的输入不是 OIDC token 本身，而是一个已经认证出的身份对象：

- `user`: 用户名字符串。
- `groups`: 用户所属组名字符串列表。
- `extra`: 可选扩展字段。

RBAC 资源中：

- `Role`/`ClusterRole` 描述允许访问哪些资源、哪些 verb。
- `RoleBinding`/`ClusterRoleBinding` 把权限绑定给 `User`、`Group` 或 `ServiceAccount`。

OIDC claim 中的 `roles` 和 Kubernetes `Role` 不是一个概念。`roles=["platform-admin-system"]` 只是 issuer 或平台声明的角色字符串，只有在当前集群 RBAC 明确把它当成 Group subject 绑定时，才能映射成 SAR 的 `groups`。

### SelfSubjectAccessReview

`SelfSubjectAccessReview` 的含义是：当前 Kubernetes 请求身份是否具备某项权限。

如果组件用自己的 ServiceAccount client 创建 SSAR，检查的是组件 ServiceAccount 的权限，不是终端用户权限。

如果组件用原始 OIDC token 创建 Kubernetes client 再发 SSAR，只有在当前 kube-apiserver 本身信任该 OIDC issuer 时才成立。真实环境已经验证，业务集群 direct API 不接受平台 id_token，因此这不能作为通用方案。

### SubjectAccessReview

`SubjectAccessReview` 允许调用方显式指定待检查的 `user` 和 `groups`：

```yaml
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: admin@cpaas.io
  groups:
    - platform-admin-system
  resourceAttributes:
    group: connectors.alauda.io
    version: v1alpha1
    resource: connectors
    subresource: apis/gitlab
    verb: get
    namespace: default
    name: example
```

Kubernetes 不要求 `spec.user` 先通过当前集群 authentication。只要创建 SAR 的组件 ServiceAccount 有 `create subjectaccessreviews` 权限，authorizer 就会用这些字符串匹配当前集群 RBAC。

这正适合 OIDC 自校验链路：

- OIDC token 真实性由组件验证。
- 当前集群资源权限由当前集群 RBAC 判断。
- 组件只负责把可信 token 映射为 RBAC subject 字符串。

## 推荐认证鉴权链路

### 1. 配置解析

共享库应支持显式配置优先，默认配置来源其次。

建议配置模型：

```go
// OIDCAuthConfig describes how to verify OIDC tokens and map claims to Kubernetes identities.
type OIDCAuthConfig struct {
    IssuerURL        string
    Audiences        []string
    UsernameClaims   []string
    GroupsClaims     []string
    RolesClaims      []string
    UserPrefix       string
    GroupPrefix      string
    RequiredClaims   map[string]string
    CAFile           string
    CAData           []byte
    ClockSkewSeconds int
}
```

默认值建议：

- `IssuerURL`: 可从 `global-info.data.oidcIssuer` 读取。
- `Audiences`: 默认使用显式传入值；ACP 默认可从 `global-info.data.oidcClientID` 读取。
- `UsernameClaims`: ACP 兼容默认 `preferred_username,email`；通用新部署建议显式配置为 `sub`。
- `GroupsClaims`: 默认不启用，除非 issuer 明确提供标准 groups claim。
- `RolesClaims`: 默认不启用；ACP 可以显式配置 `roles` 作为 group 映射来源。
- `UserPrefix`/`GroupPrefix`: 默认空字符串以兼容现有 ACP RBAC；安全新部署可显式加前缀。

`global-info` 默认读取建议单独做成 adapter，例如：

```go
// GlobalInfoOIDCConfigLoader loads OIDC defaults from kube-public/global-info.
type GlobalInfoOIDCConfigLoader interface {
    LoadOIDCAuthConfig(ctx context.Context) (*OIDCAuthConfig, error)
}
```

这样组件可以选择不用 `global-info`，直接传入完整配置。

### 2. Bearer token 提取

组件从请求中提取 token：

- 优先读取 `Authorization: Bearer <token>`。
- 是否支持 query 参数中的 `token` 应由调用方决定。Query token 容易进入日志、审计和浏览器历史，默认不建议启用。
- token 为空、格式不是 Bearer 或前缀后无内容时返回 401。

提取 token 后不要写入日志。日志中只能记录 token 是否存在、issuer、audience、claim 映射结果等非敏感信息。

### 3. Token verifier

验证器职责：

1. 通过 discovery 初始化 provider 元数据。
2. 从 JWKS 获取并缓存验签公钥。
3. 校验签名和算法。
4. 校验 `iss`。
5. 校验 `aud`。
6. 校验 `exp`、`nbf`、`iat`。
7. 返回完整 claims 给 mapper。

建议接口：

```go
// TokenVerifier verifies a raw bearer token and returns trusted claims.
type TokenVerifier interface {
    Verify(ctx context.Context, rawToken string) (*VerifiedToken, error)
}

// VerifiedToken stores verified OIDC claims.
type VerifiedToken struct {
    Issuer string
    Subject string
    Audience []string
    Claims map[string]any
}
```

失败分类建议：

- token 缺失或格式错误：401。
- issuer/audience/signature/time 校验失败：401。
- discovery/JWKS 临时不可用：503 或可标记 temporary error。
- 配置错误：启动时报错优先，运行时返回 500 并记录清晰日志。

### 4. Claims mapper

mapper 把可信 claims 转成 Kubernetes identity：

```go
// ClaimsMapper maps trusted OIDC claims to a Kubernetes authorization identity.
type ClaimsMapper interface {
    Map(ctx context.Context, token *VerifiedToken) (*KubernetesIdentity, error)
}

// KubernetesIdentity is the subject used in SubjectAccessReview.
type KubernetesIdentity struct {
    User string
    Groups []string
    Extra map[string]authv1.ExtraValue
}
```

映射策略：

- 按 `UsernameClaims` 顺序取第一个非空 string claim。
- claim 缺失或类型错误时返回 401 或配置错误，取决于该 claim 是否必需。
- `email` 作为 username 时，建议支持要求 `email_verified=true`。
- `groups` 支持 string array，也可兼容空格分隔或逗号分隔字符串，但需要显式配置。
- `roles` 只有在调用方显式配置 `RolesClaims` 时才映射到 groups。
- 支持 group allowlist、denylist 或 prefix filter，避免把平台全局角色无差别带入组件权限判断。

当前 ACP 兼容映射建议：

```yaml
usernameClaims:
  - preferred_username
  - email
rolesClaims:
  - roles
userPrefix: ""
groupPrefix: ""
```

通用新部署建议：

```yaml
usernameClaims:
  - sub
userPrefix: "oidc:"
groupsClaims:
  - groups
groupPrefix: "oidc:"
```

但使用 `sub` 时，集群内 RoleBinding/ClusterRoleBinding 必须按 `oidc:<sub>` 重新绑定，否则会像本次验证一样无法命中现有 RBAC。

### 5. SAR reviewer

reviewer 使用组件自身 ServiceAccount client 创建 `SubjectAccessReview`：

```go
// SubjectAccessReviewer checks whether an identity can access Kubernetes resources.
type SubjectAccessReviewer interface {
    Review(ctx context.Context, identity *KubernetesIdentity, attr authv1.ResourceAttributes) error
}
```

创建的 SAR 必须是 `authorization.k8s.io/v1.SubjectAccessReview`，不能是 `SelfSubjectAccessReview`。

成功条件：

- Kubernetes API create SAR 成功。
- `review.Status.Allowed == true`。

失败处理：

- `Allowed=false`: 返回 forbidden，错误中包含 resource、subresource、verb、namespace、name，不包含 token。
- `EvaluationError` 非空：记录日志，并按失败处理。
- create SAR 被拒绝：提示组件 ServiceAccount 缺少 `create subjectaccessreviews` 权限。

### 6. restful filter adapter

当前共享仓库已有 [client/rbac_filter.go](./client/rbac_filter.go)，但默认路径是 SSAR。后续可以新增独立 filter，而不是改变已有行为：

```go
// OIDCSubjectReviewFilter validates an OIDC bearer token and authorizes mapped identity by SAR.
func OIDCSubjectReviewFilter(
    ctx context.Context,
    verifier TokenVerifier,
    mapper ClaimsMapper,
    reviewer SubjectAccessReviewer,
    resourceAttGetter ResourceAttributeGetter,
) restful.FilterFunction
```

这样老组件继续使用现有 `SubjectReviewFilterForResource`，新组件或新 feature flag 路径显式启用 OIDC SAR。

## Connectors 接入建议

Connectors API 当前链路：

1. 先检查用户是否能 `get connectors`。
2. 如果 `enable-connector-apis-permissions` 启用，再检查 `connectors/apis` 子资源。
3. 在 ACP 环境中，如果 `global-info` 存在，会构造 `platformURL/kubernetes/clusterName`，拿请求 Bearer token 访问平台代理 API 做权限检查。
4. 在普通集群中，则依赖请求 token 能被当前集群 kube-apiserver 认证。

新 OIDC SAR 接入建议：

- 增加显式 provider 选择，不要继续用“存在 global-info 就必然走 Erebus”作为唯一判断。
- provider 可选值建议：
  - `kubernetes-self`: 保留现有 direct SSAR 行为。
  - `acp-erebus`: 保留现有平台代理 API 行为。
  - `oidc-sar`: 新增 OIDC 自校验 + 当前集群 SAR 行为。
- `oidc-sar` provider 可从 `global-info` 加载默认 issuer/audience，但允许组件启动参数、ConfigMap 或代码配置覆盖。
- `oidc-sar` provider 下，`connectors/apis` 权限检查应复用现有 `ConnectorsAPISubResourceAttributes` 资源属性构造逻辑，只替换 reviewer 的认证身份来源。

Connectors API 的两个检查都应走同一身份：

```text
request Bearer token
  -> OIDC verifier
  -> claims mapper: user/groups
  -> SAR get connectors
  -> SAR get connectors/apis/{connectorClassName}/{pathPattern}
```

不要第一段用 OIDC SAR、第二段又回落到 Erebus 或 direct SSAR，否则同一个请求会出现不一致的身份和权限结果。

## 公共库实现落点建议

建议在共享仓库中新增独立包，而不是把逻辑塞进 `client` 包已有 filter：

```text
auth/oidc/
  config.go
  discovery.go
  verifier.go
  claims.go
  sar.go
  restful_filter.go
```

原因：

- `client` 包当前已经同时承担 Kubernetes client manager、bearer token client config、RBAC filter 等职责。
- OIDC verifier、JWKS cache、claims mapper 是独立能力，未来不只 Connectors 会用。
- 单独包能避免在通用 `client` 包里引入过多 OIDC provider 细节。

如果希望保持更短导入路径，也可以放在：

```text
oidcauth/
```

但建议包名表达清楚它做的是 OIDC authentication 和 Kubernetes authorization adapter，而不是 OIDC login。

### 依赖选择

当前 `go.mod` 已有：

- `github.com/golang-jwt/jwt/v4`

可选方案：

1. 使用 `github.com/coreos/go-oidc/v3/oidc`
   - 优点：OIDC discovery、JWKS cache、issuer/audience/time 校验成熟。
   - 缺点：新增依赖。
2. 基于 `github.com/golang-jwt/jwt/v4` 自行实现 discovery、JWKS cache 和 claim 校验。
   - 优点：少引依赖。
   - 缺点：安全细节更多，容易漏掉 issuer/audience/alg/key rotation 等边界。

建议优先使用成熟 OIDC verifier 库，除非项目对新增依赖有明确限制。认证代码属于安全边界，不建议为了少一个依赖而手写过多协议细节。

### 与现有代码的关系

现有 [client/manager.go](./client/manager.go) 中的 `UserFromBearerToken` 只做 `ParseUnverified`，不能作为安全认证依据。它最多只能用于历史兼容或日志辅助，不能用于新 OIDC 鉴权链路。

现有 [client/rbac_filter.go](./client/rbac_filter.go) 的 `RequestSubjectAccessReview` 实际创建的是 `SelfSubjectAccessReview`。新链路需要新增显式 subject 的 SAR 方法，例如：

```go
// RequestSubjectAccessReviewForUser checks permissions for the provided Kubernetes identity.
func RequestSubjectAccessReviewForUser(
    ctx context.Context,
    clt client.Client,
    identity user.Info,
    resourceAtt authv1.ResourceAttributes,
) error
```

该方法可以复用已有 `makeSubjectAccessReview` 和 `postSubjectAccessReview`，但需要作为公开 API 暴露，并确保调用方传入的是已经由 OIDC verifier 信任的 identity。

## 安全与兼容性要求

### 必须做的安全校验

- 必须校验 JWT signature。
- 必须校验 `iss`。
- 必须校验 `aud`。
- 必须校验 `exp`，存在 `nbf` 时必须校验。
- 必须限制接受的签名算法，不能接受 `none` 或配置外算法。
- 必须禁止把未验签 claims 用作 RBAC identity。
- 日志不得输出 raw token、client secret、password、cookie。

### 建议支持的安全配置

- 自定义 CA bundle，用于私有 issuer 或 air-gapped issuer。
- JWKS cache TTL 和刷新策略。
- clock skew。
- required claims，例如要求 `email_verified=true`。
- username/group prefix。
- group allowlist/filter。
- 是否接受 query token，默认关闭。

### 兼容性策略

为了避免影响已有组件：

- 新 OIDC SAR filter 应显式启用。
- 现有 `kubernetes-self` 和 `acp-erebus` 行为保持不变。
- 默认读取 `global-info` 时，只把它当配置来源，不把 `clusterName/platformURL` 缺失视为 OIDC 配置错误。
- `global-info` 中 ACP/Erebus 字段和 OIDC 字段应分别校验，避免一个字段缺失导致另一路 provider 无法启动。

## 测试建议

### 单元测试

Token verifier：

- discovery 成功，JWKS 验签成功。
- issuer 不匹配返回 401。
- audience 不匹配返回 401。
- token 过期返回 401。
- `nbf` 在未来返回 401。
- `kid` 不存在时刷新 JWKS 后重试。
- 不接受非配置算法。

Claims mapper：

- `preferred_username` fallback `email`。
- `sub` 加 prefix。
- `email_verified=false` 时拒绝。
- `groups` string array 映射成功。
- `roles` 默认不映射，显式配置后映射。
- group filter 生效。
- username claim 缺失时报错。

SAR reviewer：

- 创建 `SubjectAccessReview`，不是 `SelfSubjectAccessReview`。
- SAR 中的 `spec.user/spec.groups` 来自 mapper。
- `Allowed=true` 放行。
- `Allowed=false` 返回 forbidden。
- create SAR 被拒绝时返回清晰错误。

REST filter：

- 缺少 Bearer token 返回 401。
- token 验证失败不会调用 SAR。
- claims 映射失败不会调用 SAR。
- SAR forbidden 不进入后续 handler。
- 成功后进入后续 handler。

### 集成测试

建议使用真实或 envtest 集群验证：

- 当前集群 direct API 不接受 OIDC id_token 时，OIDC SAR provider 仍能完成鉴权。
- `preferred_username/email` 能命中已有 RBAC 时请求允许。
- `sub` 未绑定 RBAC 时请求拒绝。
- 给 `sub` 新增 RoleBinding 后请求允许。
- 组件 ServiceAccount 缺少 `create subjectaccessreviews` 时返回清晰错误。
- `connectors/apis` feature flag 启用时，`connectors` 和 `connectors/apis` 两段权限检查使用同一 OIDC identity。

## 推荐实施顺序

1. 在共享仓库新增 OIDC verifier、claims mapper、SAR reviewer 和 restful filter。
2. 暴露显式配置结构，提供 `global-info` 默认 loader，但不强依赖它。
3. 给 `client/rbac_filter.go` 增加公开的 explicit-user SAR helper，或在新包内部实现等价逻辑。
4. 在 Connectors API 中增加 provider 选择和 feature flag，接入 `oidc-sar` provider。
5. 为 Connectors API ServiceAccount 补 `create subjectaccessreviews` 权限。
6. 增加单元测试和至少一条真实集成验证链路。

## 最终建议

这次共享机制的关键不是让业务集群 kube-apiserver 直接接受 OIDC token，而是让组件自己成为一个 OIDC-aware resource server：

- OIDC 负责证明“请求者是谁”。
- claims mapper 负责把 OIDC 身份转换成当前集群 RBAC subject。
- Kubernetes SAR 负责回答“这个 subject 能否访问目标资源”。

这种设计能同时满足：

- 不强依赖 ACP `global-info` 和 Erebus。
- 支持 air-gapped 私有 issuer。
- 支持已有 ACP RBAC 绑定。
- 支持普通 Kubernetes 集群按 `sub/groups` 重新绑定。
- 让其他组件复用同一套认证/鉴权基础设施。
