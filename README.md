# Middleware

**繁體中文** ｜ [English](README.en.md)

Mendesky 平台共用的 [Hummingbird 2.x](https://github.com/hummingbird-project/hummingbird) middleware 套件。這是一個 **library package**（非執行檔），給各個 context 服務（OpportunityContext、QuotingContext…）共用。

提供：

- **認證**：Bearer token 驗證，支援 JWE（legacy）與 at+jwt（`BearerTokenAuthenticationMiddleware`）
- **Signed access token（at+jwt）**：RS256 JWT，涵蓋第一方使用者、外部系統（application）與代理使用者（delegatedUser）；路由自行開放（`RouteAcceptance`、`Caller`、`Scope`）；測試用簽章工具在 `MiddlewareTesting`
- **授權**：endpoint-level RBAC（`PermissionMiddleware`，即時查 IAMContext）
- **CORS**：origin 白名單 + preflight（`DynamicCORSMiddleware`）
- **Logging**：請求/回應 debug log（`LoggingMiddleware`）
- **Header proxying**：把 inbound header 轉發到 outbound 服務呼叫（`ProxyHeaderReceiverMiddleware` + `ProxyHeaderSenderMiddleware`）

---

## 需求 & 安裝

- Swift 6.0+ / macOS 15+
- 相依：Hummingbird 2.x、jose-swift 6.x、swift-openapi-runtime 1.x

`Package.swift`：

```swift
.package(url: "git@github.com:Mendesky/Middleware.git", from: "1.0.0"),
// target 依賴
.product(name: "Middleware", package: "Middleware"),
```

```bash
swift build
swift test
```

---

## Middleware 一覽

| 名稱 | 類型 | 角色 |
|---|---|---|
| `BearerTokenAuthenticationMiddleware` | server（`MiddlewareProtocol`）| 驗證 Bearer token（JWE legacy 或 at+jwt）、驗身分（你是誰）|
| `PermissionMiddleware` | server（`MiddlewareProtocol`）| endpoint 權限檢查（你能不能做）|
| `DynamicCORSMiddleware<Context>` | server（`RouterMiddleware`）| origin 白名單 CORS + preflight |
| `LoggingMiddleware` | server（`MiddlewareProtocol`）| debug-level 請求/回應 log |
| `ProxyHeaderReceiverMiddleware` | server（`MiddlewareProtocol`）| 把指定 inbound header 收進 `TaskLocal` |
| `AccessTokenMiddleware` | client（`ClientMiddleware`）| 把當前請求的 `Authorization` 轉發到 outbound 呼叫 |
| `ProxyHeaderSenderMiddleware` | client（`ClientMiddleware`）| 把 `SetHeaders` 收集到的 header 附到 outbound 呼叫 |

---

## 認證：`BearerTokenAuthenticationMiddleware`

驗證 `Authorization: Bearer <token>`：token 是 JWE（legacy，5 段）或 at+jwt（3 段，見下方）；並比對 `operatorId` header（`userId` 為 deprecated fallback）防盜用。

金鑰從環境變數載入：

| 環境變數 | 必填 | 說明 |
|---|---|---|
| `MENDESKY_AUTH_RECIPIENT_JWK` 或 `..._JWK_PATH` | ✅ | 解密私鑰（JWK JSON / base64 或檔案路徑）|
| `MENDESKY_AUTH_SENDER_JWK` 或 `..._JWK_PATH` | —（正式環境建議必填）| 寄件者驗證公鑰 |
| `MENDESKY_AUTH_PASSWORD` | — | JWK 密碼（base64）|

> ⚠️ **正式環境請務必設定 `MENDESKY_AUTH_SENDER_JWK`**：未設時 JWE 只有機密性、沒有寄件者認證——任何握有 recipient **公鑰**者都能偽造 token，而本中間件完全信任 token 內的 `userId`。

```swift
router.add(middleware: try BearerTokenAuthenticationMiddleware(
    validators: [PathValidator("/health")]   // 白名單（跳過認證）
))
```

行為與 status code：

> ⚠️ **在開放給 `.application` 的路由上，`operatorId` / `userId` header 不會被驗證，會原封不動傳到 handler。** handler 不可信任它們來辨識 application 呼叫者；請讀 `Caller.current`（`if case .application(let c) = Caller.current`）。 `ProxyHeaderReceiverMiddleware` 不論是否通過驗證都會收下該 header，`ProxyHeaderSenderMiddleware` 會把它轉發到每一次下游呼叫，所以呼叫者自行指定的 `operatorId` 會連同 application token 一路傳到下游服務；下游若把 `operatorId` 記進事件，該行為就會被歸給呼叫者指定的人。

| 情況 | 回應 |
|---|---|
| OPTIONS / 白名單路徑 | 放行（跳過）|
| 沒帶 `Authorization` | `401` |
| 不是 `Bearer <token>` 格式 | `400` |
| JWE 解密失敗 / token 過期 | `401` |
| JWE：沒帶 `operatorId`（或 deprecated 的 `userId`）header | `400` |
| JWE：`operatorId` / `userId` header ≠ token 內 userId | `400`（防盜用）|
| 驗證本身出錯（token 驗證流程的非預期錯誤）| `401` |

> 白名單用 `PathValidator`（見下方），符合的路徑會跳過認證；`OPTIONS` 一律跳過（給 CORS preflight）。

### Signed access token（at+jwt）

除了使用者 JWE token，`BearerTokenAuthenticationMiddleware` 也接受 **signed access token**：RS256 簽章的 JWT（`typ: at+jwt` 或 `application/at+jwt`，header 帶 `kid`）。共有三種呼叫者：

- **user**：第一方使用者（IdentityContext 簽發，`sub_type: user`、無 `act`），對應 `.user`，所有路由都收，行為與 JWE 使用者相同。
- **application**：外部系統用 OAuth `client_credentials` 取得，**沒有使用者帳號**（`sub_type: application`，`sub` 為 applicationId，對外以小寫呈現），路由必須明確開放。
- **delegatedUser**：使用者的 token 由代理者（actor，例如 MCP server）持有（`sub_type: user` 且帶 `act`，RFC 8693），路由必須明確開放。

claims：`iss`、`aud`（`mendesky-services`，字串或陣列皆可）、`sub`、`sub_type`、`client_id`、`scope`（空白分隔，可為空字串但必須存在）、`exp`。發行者一律會設 `iat`、`jti`，但 Middleware 不要求也不檢查它們。

#### 信任設定

| 環境變數 | 必填 | 說明 |
|---|---|---|
| `MENDESKY_ACCESS_TOKEN_TRUST_PATH` | —（兩者皆未設 = 不接受 at+jwt，只走 JWE）| 信任設定 JSON 檔案路徑；兩者都設時以檔案為準 |
| `MENDESKY_ACCESS_TOKEN_TRUST` | — | 信任設定 JSON 的 base64 |

```json
{
  "audience": "mendesky-services",
  "issuers": [
    {
      "issuer": "https://<平台網域>/identity-context",
      "callerTypes": ["user"],
      "keys": { "keys": [ { "kty": "RSA", "kid": "ic-2026-11", "n": "…", "e": "AQAB" } ] }
    },
    {
      "issuer": "https://oidc.jwcpas.net/oidc-context",
      "callerTypes": ["application", "delegatedUser"],
      "actors": ["mendesky-mcp-server"],
      "keys": { "keys": [ { "kty": "RSA", "kid": "oidc-at-2026-11", "n": "…", "e": "AQAB" } ] }
    }
  ]
}
```

- `actors` 是允許的 `act.sub`；只放公鑰；不會在執行時去抓 `/jwks`。
- **設定錯誤會在啟動時 throw（服務不啟動）**，任何一條不符都算：
  - 最多一個發行者允許 `user`，而且它不能同時允許 `application` 或 `delegatedUser`；
  - 允許 `delegatedUser` 的發行者，`actors` 不可為空；
  - `issuer` 不可重複；同一個 `kid` 不可出現兩次（同一發行者內或跨發行者）；
  - 金鑰必須是 `kty=RSA`、有 `n` 與 `e`、`alg` 不存在或為 `RS256`、模數至少 2048 bit，且不可含私鑰欄位（`d`、`p`、`q`、`dp`、`dq`、`qi`）。
- ⚠️ `MENDESKY_APP_TOKEN_*` 已改名為上面兩個變數；舊變數只要設了任何一個就會啟動失敗（錯誤訊息指出要改用哪個變數）。
- `init(verification:validators:)` **永遠不讀** `MENDESKY_ACCESS_TOKEN_TRUST`：用這個 init 時，即使環境變數有設，at+jwt 也不會被接受，也不會有任何 log 提示。要啟用 at+jwt，請用 `init(validators:)`、`init(validators:accepting:)`，或明確傳入 `trust:` 的 init。
- 會讀環境變數的 init（`init(validators:)`、`init(validators:accepting:)`、`init(validators:acceptsApplication:)`）啟動時都會寫 notice log：`Signed access tokens enabled: ...`（列出 audience 與各發行者的 callerTypes、actors、kid）或 `Signed access tokens disabled: ...`，以及 `Legacy JWE mode: accept|warn|reject`。

#### 舊 JWE 開關：`MENDESKY_LEGACY_JWE`

| 值 | 行為 |
|---|---|
| `accept`（預設，未設或空白）| 照常解密 JWE；每個通過的請求記一行 `legacy-jwe-accepted`（`.notice`）|
| `warn` | 同上，但以 `.warning` 記錄 |
| `reject` | 5 段 token 不解密，記 `legacy-jwe-rejected`（`.notice`）並回 `401` |

其他值會啟動失敗。**只有**讀環境變數的 init 會讀這個變數：Bearer 的 `init(validators:)`、`init(validators:accepting:)`、`init(validators:acceptsApplication:)`，以及 `PermissionMiddleware.init(rules:provider:)`（沒有 Bearer 在前面時的 JWE fallback 同樣遵守此開關）。明確傳參數的 init（Bearer 的 `init(verification:validators:)`、`init(verification:applicationTokens:validators:acceptsApplication:logger:)` 永遠是 `accept`；`init(verification:trust:legacyJWE:…)` 預設 `accept`；`PermissionMiddleware.init(rules:provider:verification:…)`）使用傳入的值（或 `accept`），**忽略**此環境變數。`legacy-jwe-accepted` 的 metadata 只有 `clientId`（JWE 內的 clientId，第一方為空字串）、`route`（路由樣板如 `/items/{id}`，不是實際路徑；取不到時為 `unknown`）、`service`（預設為 process 名稱，可由 init 參數覆寫）；`legacy-jwe-rejected` 只有 `route`、`service`。log **不含 token、不含 userId**。若 `PermissionMiddleware` 放在 Bearer 前面，同一個 JWE 會被記兩次 `legacy-jwe-accepted`，Permission 也會先記下之後被 Bearer 以 `400` 擋掉的請求；計數只會多算、不會少算，不影響用「計數歸零」判斷能否移除 JWE。

#### 開放路由：`accepting: [RouteAcceptance]`

```swift
router.add(middleware: try BearerTokenAuthenticationMiddleware(
    validators: [PathValidator("/health")],
    accepting: [
        // application token：只有符合的路由才收
        .application(PathValidator("/notification-context/notifications"), methods: [.post]),
        // 代理使用者 token：scope 必須「剛好」含 quote:read，且 actor 限定
        .delegatedUser(
            PathValidator("/quoting-context/drafts"),
            requiresScope: "quote:read",
            actors: ["mendesky-mcp-server"]
        ),
    ]
))
```

- 第一方 user（JWE 或 at+jwt）不需要開放，所有路由都收。
- ⚠️ **在開放給 `.application` 的路由上，`operatorId` / `userId` header 不會被驗證，會原封不動傳到 handler。** application 呼叫者沒有使用者，handler 不可信任這些 header；請讀 `Caller.current`（`if case .application(let c) = Caller.current`）取得呼叫者。 `ProxyHeaderReceiverMiddleware` 不論是否通過驗證都會收下該 header，`ProxyHeaderSenderMiddleware` 會把它轉發到每一次下游呼叫，所以呼叫者自行指定的 `operatorId` 會連同 application token 一路傳到下游服務；下游若把 `operatorId` 記進事件，該行為就會被歸給呼叫者指定的人。
- 同一條路由符合多個 `RouteAcceptance` 時是**聯集（OR）**：只要任一條放行就放行。之後再加一條較寬的規則（例如不限 actor），會靜默放寬原本有 actor 限定的那條。
- 舊的 `BearerTokenAuthenticationMiddleware(acceptsApplication:)` 仍可用，等同 `accepting: [.application(where:)]`。
- `.delegatedUser` 的 `actors: nil` 表示接受該發行者信任清單內的任何 actor；`requiresScope` 用精確比對，**不適用 `*`**，且代理 token 的任一 scope 項目只要含 `*` 字元（例如 `*`、`quote:*`）一律拒絕。
- `PathValidator(try Regex(...))` 比對的是**原始請求路徑**。範例請寫 `[^/]+`（單一路徑段）而不是 `.+`：`/quotes/.+` 也會匹配 `/quotes/1/admin`，等於把子路徑一併開放。例如 `PathValidator(try Regex("/quotes/[^/]+"))`。

行為與 status code（at+jwt 部分，其餘同上表）：

| 情況 | 回應 |
|---|---|
| 3 段 token 但沒設信任設定 / 驗章失敗 / 過期 / 不符 `callerTypes` | `401` |
| token 段數既不是 3 也不是 5 | `401` |
| 路由沒開放該身分（或 actor 不符路由限定）| `401` |
| `.delegatedUser`：路由開放且 actor 符合，但 scope 不含 `requiresScope` | `403`（body `insufficient scope.`）|
| `.user` 與 `.delegatedUser`：沒帶 `operatorId` 或 ≠ `sub` | `400`（`userId` header 為 deprecated fallback）|
| `.application` | 不需要 `operatorId`；若有帶也**不驗證**，原樣傳給 handler（見上方警告）|
| 5 段 token 且 `MENDESKY_LEGACY_JWE=reject` | `401` |

驗證只收 RS256（固定演算法、不從 token 取），header 必須剛好是 `{alg, typ, kid}`（多帶 `crit`、`jwk` 等參數一律拒收），並檢查 `typ`、`kid`、簽章、`iss`、`aud`、`exp`，且 `sub`、`sub_type`、`client_id`、`scope` 必須存在；失敗的原因記在 log，**絕不記 token**。

#### 在 handler 裡取得呼叫者

```swift
if case .application(let claims) = Caller.current {
    guard Scope.grants(claims.scope, Scope.notificationSend) else { throw HTTPError(.forbidden) }
}
```

- `Caller.current` 是 task-local 的 `CallerIdentity?`：`.user(userId:clientId:)`、`.application(ApplicationTokenClaims)`、`.delegatedUser(DelegatedUserClaims)`；之後可能新增案例，所以請用 `if case` 而不要寫窮舉 `switch`。
- `Scope.grants(held, required)`：持有 `*`（`Scope.all`）或剛好等於 required 即通過；`Scope.notificationSend` = `notification:send`。

#### 金鑰輪替與限制

- 同一發行者可以放多把公鑰，輪替步驟：(1) 把新公鑰加進信任設定並部署各服務；(2) 發行者切換到新私鑰；(3) 移除舊公鑰。
- `aud` 在整個平台共用 `mendesky-services`，所以任何收到 token 的服務都能拿它去呼叫其他服務；這與現行 JWE 相同，也是 token 轉發（forwarding）能運作的原因。`.delegatedUser` token 被轉發到沒有對 delegatedUser 開放的下游路由時，會得到 `401`。
- `reject` 模式仍需要設定 JWE 金鑰（`MENDESKY_AUTH_*`），直到下個主版本移除 JWE 為止。
- `MENDESKY_ACCESS_TOKEN_TRUST` 的 base64 必須是**單行**（GNU 用 `base64 -w0`，macOS 用 `base64 -i file`）；有換行的值會讓服務啟動失敗。
- ⚠️ `jti` **不提供重放保護**；停用某個 client 後，已簽發的 token 仍有效直到 `exp`（最長 15 分鐘）。
- `PermissionMiddleware` **必須排在 Bearer middleware 之後**，才收得到 at+jwt 呼叫者（它讀 `Caller.current`）。`.user` 與 `.delegatedUser` 都會以 `sub` 查 IAM；`.application` 沒有 IAM user，**永遠不放行**，所以開放 application 的路由不可同時是 `PermissionRule` 路由。
- 升級既有服務時的行為變更：token 驗證失敗一律 `401`（部分原本是 `503`）；handler 丟出的錯誤：符合 Hummingbird `HTTPResponseError` 的保留原本狀態碼（404 仍是 404），其他錯誤仍是 `503`（body 為固定的 `service unavailable.`，log 只記錯誤型別）；token 永不寫進 log。application token 現在必須帶 `sub_type: "application"`，金鑰規則也跟著變嚴（≥ 2048 bit、不可含私鑰欄位）。

---

## 授權：`PermissionMiddleware`（endpoint-level RBAC）

掛在 `BearerTokenAuthenticationMiddleware` 後面。對「有規則涵蓋」的路由：先讀 `Caller.current` 拿 `userId`（JWE 解密只是 deprecated 的後備）→ 透過 `PermissionsProvider` 取得該 user 的權限 → 跟規則要求的權限做 **AND** 比對（exact string match）→ 放行或擋。

### 三個角色（責任邊界）

| 東西 | 住哪 | 職責 |
|---|---|---|
| 權限字彙 + 「誰有哪些權限」 | **IAMContext** | 權威來源（grant/revoke、getPermissions）|
| 「路由→所需權限」規則表 | **各 context 自己** | 啟動時灌進 `PermissionMiddleware(rules:)` |
| 比對引擎 | **本套件** | `PermissionMiddleware` / `PermissionRule`，**不持有任何具體規則或權限字串** |

> 本套件**刻意不依賴 IAMContext**。真正打 IAM 的 HTTP client 由消費端以 `PermissionsProvider` 注入（見「接線範例」）。

### `PermissionRule`

```swift
PermissionRule(
    _ pathMatcher: any WhitelistValidator,     // 路徑比對（用 PathValidator）
    methods: Set<HTTPRequest.Method>? = nil,   // 限定 method；nil = 不限
    requires: [String]                          // 所需權限（AND，全部具備才放行）
)
```

### `PermissionsProvider`（port）

```swift
public protocol PermissionsProvider: Sendable {
    func permissions(forUserId userId: String) async throws -> [String]
}
```

- `ClosurePermissionsProvider { userId in ... }` — 用 closure 快速注入。
- `CachingPermissionsProvider(wrapping:ttl:negativeTTL:maxEntries:)` — actor、per-userId、單調時鐘 TTL（預設 60s）、**只快取成功**、`invalidate(userId:)` / `invalidateAll()`。空結果（IAM 404→`[]`）改用較短的 `negativeTTL`（預設 10s；`nil` = 不快取空結果），避免剛開通的 user 在整個 `ttl` 內被擋；`maxEntries`（預設 500）限制記憶體，額滿時先淘汰過期、再淘汰最舊。

### Status code

| 情況 | 回應 |
|---|---|
| OPTIONS | 放行（跳過）|
| 沒有規則涵蓋此路由 | 放行 |
| 命中規則但拿不到可信 token | `401` |
| provider（IAM 查詢）失敗 | `502`（fail-closed；用 502 而非 503，以區分「上游依賴故障」）|
| 缺所需權限 | `403` |
| 權限齊全 | 放行進 handler |

---

## 接線範例（以 OCServer 為例）

```swift
// (1) Token 解密金鑰：從 MENDESKY_AUTH_* 環境變數載入
let verification = try AccessTokenVerification.fromEnvironment()

// (2) 權限來源：IAM adapter（真正打 IAMContext 的 client）+ 快取
//     base URL 走環境變數，別 hardcode
let iamBase = Environment().get("IAM_BASE_URL") ?? "http://localhost:24202"
let iamProvider = ClosurePermissionsProvider { userId in
    let encoded = userId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? userId
    let url = URL(string: "\(iamBase)/employee-access/permissions/\(encoded)")!
    let (data, resp) = try await URLSession.shared.data(from: url)
    switch (resp as? HTTPURLResponse)?.statusCode {
    case 200: return try JSONDecoder().decode([String].self, from: data)
    case 404: return []                            // 沒 profile = 沒權限
    default:  throw URLError(.badServerResponse)    // → middleware 回 502
    }
}
let provider = CachingPermissionsProvider(wrapping: iamProvider, ttl: .seconds(60))

// (3) 路由→所需權限 規則表（這個 context 自己的政策）
//     ⚠️ PathValidator("字串") 是「字面」比對；要 regex 必須用 PathValidator(try Regex(...))
//     ⚠️ regex 比對原始請求路徑：用 [^/]+ 而不是 .+（否則 /…/audit-quotings/1/admin 也會命中）
let rules: [PermissionRule] = [
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/[^/]+/total-assets")),
          methods: [.patch], requires: ["business:write"]),
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/[^/]+")),
          methods: [.get],   requires: ["business:read"]),
]

// (4) 組 middleware chain（順序：認證 → 授權）
let router = Router()
router.add(middleware: DynamicCORSMiddleware(allowedOrigins: ["https://app.mendesky.com"]))
router.add(middleware: try BearerTokenAuthenticationMiddleware())          // 認證
router.add(middleware: PermissionMiddleware(rules: rules,                  // 授權
                                            provider: provider,
                                            verification: verification))
router.add(middleware: LoggingMiddleware())
try api.registerHandlers(on: router, serverURL: URL(string: "/opportunity-context")!)
```

> `PermissionMiddleware` 必須排在 `BearerTokenAuthenticationMiddleware` 之後，才看得到 at+jwt 的呼叫者（它讀 `Caller.current`；Bearer 在後或沒有 Bearer 時只會退回舊的 JWE 解析，且已標 deprecated）。
>
> `PermissionMiddleware` 另有 `init(rules:provider:)`（throws），會自己從 `MENDESKY_AUTH_*` 載入 verification，省去第 (1) 步。

### 一次請求的流向

```
前端 ──HTTP──▶ CORS ─▶ BearerTokenAuth（驗證 JWE/at+jwt、驗 operatorId、設定 Caller.current）─▶ PermissionMiddleware ─▶ handler
                                                              │ 1. method/path 比對 rules → 算出本請求所需權限
                                                              │ 2. 讀 Caller.current 拿 userId（沒有時才退回解密 JWE，已 deprecated）
                                                              │ 3. provider 取該 user 權限（命中快取就不打 IAM）
                                                              │ 4. AND 比對 → 放行 / 401 / 403 / 502
                                                              ▼
                                          provider 未命中 ──HTTP──▶ IAMContext GET /employee-access/permissions/{userId}
```

受保護請求必帶：`Authorization: Bearer <token>`（at+jwt 或 legacy JWE）與 `operatorId: <id>`（須等於 token 內的使用者 id；`userId` 為 deprecated fallback）。application token 不需要 `operatorId`。

> ⚠️ **在開放給 `.application` 的路由上，`operatorId` / `userId` header 不會被驗證，會原封不動傳到 handler。** handler 對 application 呼叫者不可信任它們，請讀 `Caller.current`（`if case .application(let c) = Caller.current`）。 `ProxyHeaderReceiverMiddleware` 不論是否通過驗證都會收下該 header，`ProxyHeaderSenderMiddleware` 會把它轉發到每一次下游呼叫，所以呼叫者自行指定的 `operatorId` 會連同 application token 一路傳到下游服務；下游若把 `operatorId` 記進事件，該行為就會被歸給呼叫者指定的人。

---

## CORS：`DynamicCORSMiddleware`

```swift
DynamicCORSMiddleware<Context>(
    allowedOrigins: ["https://app.mendesky.com"],
    allowedMethods: [.get, .post, .put, .delete, .options],   // 預設
    allowedHeaders: [.contentType, .authorization],            // 預設
    allowCredentials: true,                                    // 預設
    maxAge: 3600                                               // 預設
)
```

只有在白名單內的 origin 才會回 CORS header；`OPTIONS` preflight 回 `204 No Content`。

---

## Logging：`LoggingMiddleware`

```swift
router.add(middleware: LoggingMiddleware())
```

debug-level 記錄請求/回應。

---

## Header proxying

跨服務呼叫時把 inbound header 轉發出去，靠 `SetHeaders` 這個 `TaskLocal` 串起來：

```swift
// server 端：收集指定 header
router.add(middleware: ProxyHeaderReceiverMiddleware(presetKeys: [.init("operatorId")!]))

// client 端（OpenAPI client）：把收集到的 header 附到 outbound 請求
let client = Client(serverURL: ..., transport: ..., middlewares: [
    AccessTokenMiddleware(),        // 轉發 Authorization
    ProxyHeaderSenderMiddleware(),  // 轉發 SetHeaders 收集到的 header
])
```

`ProxyHeaderReceiverMiddleware`（server）+ `ProxyHeaderSenderMiddleware`（client）成對使用，在**同一個 async task** 內把 inbound header 透傳到 outbound 服務呼叫。

---

## 測試

```bash
swift test                                  # 全部單元測試（不依賴外部服務）
```

對真實 IAMContext 的端到端整合測試以 `IAM_BASE_URL` 守門，平時自動 skip：

```bash
IAM_BASE_URL=http://localhost:24202 swift test --filter LiveIAMIntegrationTests
```

`MiddlewareTesting` product 提供 `AccessTokenTestSigner`（即 `ApplicationTokenTestSigner`），在測試裡簽 at+jwt（RS256）：

```swift
let signer = AccessTokenTestSigner()
// 這個 signer 當成受信任發行者，並產生 MENDESKY_ACCESS_TOKEN_TRUST 格式的 base64
let issuer = signer.trustedIssuer(callerTypes: [.application, .delegatedUser], actors: ["mendesky-mcp-server"])
let trust = AccessTokenTestSigner.trustBase64(issuers: [issuer])

let app = signer.token(sub: "app-1", scope: "notification:send")                      // application（預設 subType: "application"）
let delegated = signer.token(sub: "user-1", scope: "quote:read",
                             subType: "user", actors: ["mendesky-mcp-server"])        // 代理使用者（actors 由外而內巢狀成 act）
```

- `trustedIssuer(callerTypes:actors:)` 與 `trustBase64(audience:issuers:)` 建出信任設定；`rawToken(headerData:payloadData:)` 可手工組出畸形 token 測驗證器的拒絕路徑。

> `MiddlewareTesting` **只給測試用**，production target 不要依賴它。

---

## 設計筆記

- **`PermissionMiddleware` 不打 IAMContext**：它只呼叫注入的 `PermissionsProvider`（port）。真正的 HTTP client 由消費端提供——讓本套件保持零 IAM 依賴、可單獨編譯與測試（單元測試注入 fake provider，0 網路）。
- **IAM client 該放哪**：建議放在 IAMContext 的 client 產物 / 共用 client 套件（implement `PermissionsProvider`），而非塞進本套件——「誰提供 API，誰擁有 client」。
- **權限新鮮度**：IAMContext 投影為最終一致（grant/revoke 後 ~1–2s 才反映）；快取 `ttl` / `negativeTTL` 與 `invalidate(userId:)` 是控制新鮮度的旋鈕。
- **寄件者認證**：JWE 的 `senderKey` 為選用，但未設時 token 只有機密性、無法驗證簽發者——正式環境務必設定 `MENDESKY_AUTH_SENDER_JWK`，否則握有 recipient 公鑰者可偽造 token（本中間件以 token 內 `userId` 為唯一授權輸入）。
- **粗粒度**：本層是 endpoint 級檢查（「能不能呼叫這個 endpoint」）；resource 級規則（「能不能改這一筆」）仍須在 handler 內做。
