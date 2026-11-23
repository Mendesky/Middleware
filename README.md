# Middleware

**繁體中文** ｜ [English](README.en.md)

Mendesky 平台共用的 [Hummingbird 2.x](https://github.com/hummingbird-project/hummingbird) middleware 套件。這是一個 **library package**（非執行檔），給各個 context 服務（OpportunityContext、QuotingContext…）共用。

提供：

- **認證**：Bearer token 驗證，只接受 at+jwt（`BearerTokenAuthenticationMiddleware`；2.0 起移除 legacy JWE，見「從 1.3 升級到 2.0」）
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
.package(url: "git@github.com:Mendesky/Middleware.git", from: "2.0.0"),
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
| `BearerTokenAuthenticationMiddleware` | server（`MiddlewareProtocol`）| 驗證 Bearer token（at+jwt）、驗身分（你是誰）|
| `PermissionMiddleware` | server（`MiddlewareProtocol`）| endpoint 權限檢查（你能不能做）|
| `DynamicCORSMiddleware<Context>` | server（`RouterMiddleware`）| origin 白名單 CORS + preflight |
| `LoggingMiddleware` | server（`MiddlewareProtocol`）| debug-level 請求/回應 log |
| `ProxyHeaderReceiverMiddleware` | server（`MiddlewareProtocol`）| 把指定 inbound header 收進 `TaskLocal` |
| `AccessTokenMiddleware` | client（`ClientMiddleware`）| 把當前請求的 `Authorization` 轉發到 outbound 呼叫 |
| `ProxyHeaderSenderMiddleware` | client（`ClientMiddleware`）| 把 `SetHeaders` 收集到的 header 附到 outbound 呼叫 |

---

## 認證：`BearerTokenAuthenticationMiddleware`

驗證 `Authorization: Bearer <token>`：token 必須是 at+jwt（3 段，見下方「Signed access token」）；並比對 `operatorId`（`userId` 為 deprecated fallback）與 `applicationId` header，確保 header 與 token 一致、不能指定別人（見下方「呼叫者 header」）。

信任設定（`MENDESKY_ACCESS_TOKEN_TRUST` 或 `MENDESKY_ACCESS_TOKEN_TRUST_PATH`，見下方「信任設定」）**必填**：讀環境變數的 init 在兩者都沒設時會 throw `BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured`（服務不啟動）。不讀環境變數的寫法是 `init(trust:validators:accepting:serviceName:logger:)`。

> 2.0 起 legacy JWE（5 段）一律 `401`，`MENDESKY_AUTH_*` 與 `MENDESKY_LEGACY_JWE` 不再讀取；仍有設的話啟動時會記**一行** warning 列出變數名稱（不含值），請移除這些變數並刪掉 JWE 私鑰。

```swift
router.add(middleware: try BearerTokenAuthenticationMiddleware(
    validators: [PathValidator("/health")]   // 白名單（跳過認證）
))
```

行為與 status code：

| 情況 | 回應 |
|---|---|
| OPTIONS / 白名單路徑 | 放行（跳過）|
| 沒帶 `Authorization` | `401` |
| 不是 `Bearer <token>` 格式 | `400` |
| token 驗證失敗 / 過期 | `401`（body `access token rejected.`）|
| legacy JWE（5 段 token）| `401`（body `access token rejected.`；不解密）|
| 沒帶 `operatorId`（或 deprecated 的 `userId`）header，或 ≠ token 內 userId | `400`（確保 header 與 token 一致、不能指定別人）|
| `.user`：`applicationId` header 有帶但 ≠ `mendesky-first-party`，或重複 | `400` |
| `.user`：沒帶 `applicationId` | 放行，傳下去的請求補上 `applicationId: mendesky-first-party` |
| 驗證本身出錯（token 驗證流程的非預期錯誤）| `401` |

> 白名單用 `PathValidator`（見下方），符合的路徑會跳過認證；`OPTIONS` 一律跳過（給 CORS preflight）。`PathValidator` 比對前會先照 Hummingbird router 的切法正規化路徑（去掉空 segment），所以 `/health/`、`//health` 與 `/health` 視為同一條路徑。

### 呼叫者 header：`operatorId` 與 `applicationId`

通過路由開放檢查後，Middleware 依身分比對兩個 header（名稱見 `CallerHeaders`），**精確、區分大小寫**，比對對象就是 `Caller.current` 裡的值；缺少、不符或重複都回 `400`（目的是確保 header 與 token 一致、不能指定別人；拿到 token 的人本來就讀得到裡面的值，所以這不能防止 token 被盜用）：

| 身分 | `operatorId` | `applicationId` |
|---|---|---|
| `.user` | 必帶，= token 內 userId（`sub`），原樣比對 | 選帶。沒帶時 Middleware 在傳給下一層的請求補上 `applicationId: mendesky-first-party`（`CallerHeaders.firstPartyApplicationId`）；有帶則必須剛好是它 |
| `.delegatedUser` | 必帶，= `sub` | 必帶，= actor（`act.sub`，例如 `mendesky-mcp-server`）|
| `.application` | 必帶，= applicationId | 必帶，= applicationId |

- `operatorId` 與 deprecated 的 `userId` header 必須一致：任何一個重複就回 `400`（不論另一個有沒有帶）；兩個都帶時必須逐位元組相同，否則回 `400`（handler 會把 `userId` 當成操作者，兩者不一致會讓呼叫者以別人的名義寫入事件）；只帶一個時，用那個值與 token 比對。`userId` **永遠不能**代替 `applicationId`。
- 識別碼（`operatorId`、`userId`、`applicationId`）以 **UTF-8 位元組**逐一比對，不採 Unicode 正規等價：`é` 寫成 U+00E9 與寫成 `e` + U+0301 視為不同（回 `400`）。
- `.application` 的 applicationId 是 token `sub` 轉小寫後的值，header 必須帶小寫（帶大寫 UUID 會 `400`），所以 handler 從 header 讀到的值一定等於 `Caller.current`。
- `.application` 的 `operatorId` 目前等於 applicationId；之後會改為該 application 綁定的 service account。
- 白名單路徑與 `OPTIONS` 不檢查、也不補 header。

### Signed access token（at+jwt）

`BearerTokenAuthenticationMiddleware` 只接受 **signed access token**：RS256 簽章的 JWT（`typ: at+jwt` 或 `application/at+jwt`，header 帶 `kid`）。共有三種呼叫者：

- **user**：第一方使用者（IdentityContext 簽發，`sub_type: user`、無 `act`），對應 `.user`，所有路由都收。
- **application**：外部系統用 OAuth `client_credentials` 取得，**沒有使用者帳號**（`sub_type: application`，`sub` 為 applicationId，對外以小寫呈現），路由必須明確開放。
- **delegatedUser**：使用者的 token 由代理者（actor，例如 MCP server）持有（`sub_type: user` 且帶 `act`，RFC 8693），路由必須明確開放。

claims：`iss`、`aud`（`mendesky-services`，字串或陣列皆可）、`sub`、`sub_type`、`client_id`、`scope`（空白分隔，可為空字串但必須存在）、`exp`（必須是 JSON 數字：`"exp": true` 回 `401`，不會被當成 1）；`nbf` 可有可無，有的話必須是 JSON 數字（布林、字串都不算）且不晚於現在（和 `exp` 一樣不留時鐘誤差），否則回 `401`。發行者一律會設 `iat`、`jti`，但 Middleware 不要求也不檢查它們。

#### 信任設定

| 環境變數 | 必填 | 說明 |
|---|---|---|
| `MENDESKY_ACCESS_TOKEN_TRUST_PATH` | ✅ 二擇一（兩者皆未設 = 啟動失敗）| 信任設定 JSON 檔案路徑；兩者都設時以檔案為準 |
| `MENDESKY_ACCESS_TOKEN_TRUST` | ✅ 二擇一 | 信任設定 JSON 的 base64 |

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
- ⚠️ `MENDESKY_APP_TOKEN_*` 已改名為上面兩個變數；舊變數只要設了任何一個就會啟動失敗（錯誤訊息指出要改用哪個變數）。這只適用於會讀環境變數的入口：Bearer 的 `init(validators:)`、`init(validators:accepting:)`、`init(validators:acceptsApplication:)` 與 `AccessTokenTrust.fromEnvironment(_:)`；明確傳入參數的 `init(trust:…)` 完全不讀環境變數。
- 會讀環境變數的 init（`init(validators:)`、`init(validators:accepting:)`、`init(validators:acceptsApplication:)`）啟動時會寫 notice log：`Signed access tokens enabled: ...`（列出 audience 與各發行者的 callerTypes、actors、kid）；若還設著 1.x 的 `MENDESKY_AUTH_*` / `MENDESKY_LEGACY_JWE`，另寫一行 warning 列出這些變數名稱。

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
            methods: [.get],
            requiresScope: "quote:read",
            actors: ["mendesky-mcp-server"]
        ),
    ]
))
```

- `methods:` 限定 `RouteAcceptance` 開放的 method（`nil` = 不限）：不寫的話，持有 `quote:read` 的呼叫者也能 `POST` 該路由。`HEAD` 請求會符合 `methods` 含 `GET` 的項目。
- 第一方 user 不需要開放，所有路由都收。
- `.application` 與 `.delegatedUser` 都必須帶 `operatorId` 與 `applicationId`，規則見上方「呼叫者 header」。
- 同一條路由符合多個 `RouteAcceptance` 時是**聯集（OR）**：只要任一條放行就放行。之後再加一條較寬的規則（例如不限 actor），會靜默放寬原本有 actor 限定的那條。
- 舊的 `BearerTokenAuthenticationMiddleware(acceptsApplication:)` 仍可用，等同 `accepting: [.application(where:)]`。
- `.delegatedUser` 的 `actors: nil` 表示接受該發行者信任清單內的任何 actor；`requiresScope` 用精確比對，**不適用 `*`**，且代理 token 的任一 scope 項目只要含 `*` 字元（例如 `*`、`quote:*`）一律拒絕。
- `PathValidator(try Regex(...))` 比對的是**原始請求路徑**。範例請寫 `[^/]+`（單一路徑段）而不是 `.+`：`/quotes/.+` 也會匹配 `/quotes/1/admin`，等於把子路徑一併開放。例如 `PathValidator(try Regex("/quotes/[^/]+"))`。

行為與 status code（at+jwt 部分，其餘同上表）：

| 情況 | 回應 |
|---|---|
| 驗章失敗 / 過期 / 不符 `callerTypes` | `401` |
| token 段數不是 3（5 段的 legacy JWE 也是）| `401` |
| 路由沒開放該身分（或 actor 不符路由限定）| `401` |
| `.delegatedUser`：路由開放且 actor 符合，但 scope 不含 `requiresScope` | `403`（body `insufficient scope.`）|
| `.user` 與 `.delegatedUser`：沒帶 `operatorId` 或 ≠ `sub` | `400`（deprecated 的 `userId` header 可代替，但兩者都帶時必須相同）|
| `.application`：沒帶 `operatorId` 或 ≠ applicationId（小寫）| `400`（有帶的 `userId` 也必須等於它）|
| `.delegatedUser`：沒帶 `applicationId` 或 ≠ actor（`act.sub`）| `400` |
| `.application`：沒帶 `applicationId` 或 ≠ applicationId（小寫）| `400` |
| `.user`：`applicationId` 有帶但 ≠ `mendesky-first-party`；或任何身分帶了重複的 `applicationId` | `400` |
| 任何身分：重複的 `operatorId`；重複的 `userId`（即使有帶 `operatorId`）；或 `operatorId` 與 `userId` 都帶但不是逐位元組相同 | `400` |
| 任何身分：`operatorId` / `userId` / `applicationId` 只在 Unicode 正規等價（NFC 對 NFD）下才等於預期值 | `400`（逐位元組比對）|
| at+jwt：`exp` 缺少或不是 JSON 數字（布林不算），或已過期 | `401` |
| at+jwt：`nbf` 不是 JSON 數字，或晚於現在 | `401` |

驗證只收 RS256（固定演算法、不從 token 取），header 必須剛好是 `{alg, typ, kid}`（多帶 `crit`、`jwk` 等參數一律拒收），並檢查 `typ`、`kid`、簽章、`iss`、`aud`、`exp`、`nbf`（有帶才檢查），且 `sub`、`sub_type`、`client_id`、`scope` 必須存在；失敗的原因記在 log，**絕不記 token**。

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
- `aud` 在整個平台共用 `mendesky-services`，所以任何收到 token 的服務都能拿它去呼叫其他服務；這與 1.x 的 JWE 相同，也是 token 轉發（forwarding）能運作的原因。`.delegatedUser` token 被轉發到沒有對 delegatedUser 開放的下游路由時，會得到 `401`。
- `MENDESKY_ACCESS_TOKEN_TRUST` 的 base64 必須是**單行**（GNU 用 `base64 -w0`，macOS 用 `base64 -i file`）；有換行的值會讓服務啟動失敗。
- ⚠️ `jti` **不提供重放保護**；停用某個 client 後，已簽發的 token 仍有效直到 `exp`（最長 15 分鐘）。
- `PermissionMiddleware` **必須排在 Bearer middleware 之後**（它只讀 `Caller.current`；沒有呼叫者就 `401`）。`.user` 與 `.delegatedUser` 都會以 `sub` 查 IAM；`.application` 沒有 IAM user，**永遠不放行**，所以開放 application 的路由不可同時是 `PermissionRule` 路由。
- 升級既有服務時的行為變更：token 驗證失敗一律 `401`（部分原本是 `503`）；handler 丟出的錯誤：符合 Hummingbird `HTTPResponseError` 的保留原本狀態碼（404 仍是 404），其他錯誤仍是 `503`（body 為固定的 `service unavailable.`，log 只記錯誤型別）；token 永不寫進 log。application token 現在必須帶 `sub_type: "application"`，金鑰規則也跟著變嚴（≥ 2048 bit、不可含私鑰欄位）。

---

## 從 1.3 升級到 2.0

2.0 移除 legacy JWE access token，只接受 RS256 簽章的 at+jwt。各服務 `main.swift` 的 `try BearerTokenAuthenticationMiddleware(...)`（`validators:`、`accepting:`、`acceptsApplication:` 三種寫法）與 `try PermissionMiddleware(rules:provider:)` 原樣可編譯；要改的是部署設定與少數 API：

1. **信任設定變成必填**：`MENDESKY_ACCESS_TOKEN_TRUST` 或 `MENDESKY_ACCESS_TOKEN_TRUST_PATH` 至少設一個，否則啟動時 throw `BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured`（錯誤訊息只列變數名稱）。1.3 時兩者都沒設只是「不接受 at+jwt」。**trust 必須把 IdentityContext 列為 user 發行者（`callerTypes: ["user"]`）**：1.3 時只列 application／delegatedUser 發行者的 trust 還能用（使用者走 JWE），升 2.0 後一樣能啟動，但所有第一方使用者都會 `401`。讀環境變數的 init 在沒有任何發行者接受 user token 時會記一行 warning（`No issuer in the access token trust is trusted for user tokens: ...`）。
2. **`MENDESKY_AUTH_*` 與 `MENDESKY_LEGACY_JWE` 不再讀取**（`MENDESKY_AUTH_RECIPIENT_JWK`、`MENDESKY_AUTH_RECIPIENT_JWK_PATH`、`MENDESKY_AUTH_SENDER_JWK`、`MENDESKY_AUTH_SENDER_JWK_PATH`、`MENDESKY_AUTH_PASSWORD`、`MENDESKY_LEGACY_JWE`）：還設著也不會啟動失敗，只會在啟動時記一行 warning 列出變數名稱（不含值）。請從部署設定移除，並刪除 JWE 私鑰。（`MENDESKY_APP_TOKEN_*` 仍和 1.3 一樣會讓啟動失敗。）
3. **`init(verification:…)` → `init(trust:…)`**：所有帶 `verification:` 的 init 都移除了，包括 Bearer 的 `init(verification:validators:)`、`init(verification:trust:legacyJWE:…)`、`init(verification:applicationTokens:validators:acceptsApplication:logger:)`，以及 `PermissionMiddleware.init(rules:provider:verification:…)`。不讀環境變數時改用：
   ```swift
   BearerTokenAuthenticationMiddleware(trust: trust, validators: [...], accepting: [...])   // trust 不可為 nil
   try PermissionMiddleware(rules: rules, provider: provider)
   ```
   原本的 `init(verification:applicationTokens:…acceptsApplication:)` 改成 `init(trust:accepting: [.application(where:)])`，trust 裡同時列出第一方 user 的發行者。`AccessTokenVerification` 只剩 `bearerToken(fromHeaderValue:)`、`operatorId(fromHeaders:)` 兩個 static 方法；`AccessTokenPayload`、`LegacyJWEMode`、`LegacyJWEModeError`、`BearerTokenAuthenticationMiddlewareError.recipientKeyNotFoundInEnvironment` 都已移除。
4. **5 段 token → `401`**：body `access token rejected.`，不解密；log 為 notice `Bearer token rejected: legacy JWE access tokens are no longer accepted`（metadata 只有 `route`、`service`，不含 token）。`legacy-jwe-accepted` / `legacy-jwe-rejected` 不再出現。
5. **`PermissionMiddleware` 前面必須有 Bearer**：它不再自己解 JWE；沒有 `Caller.current` 時，命中規則的請求一律 `401`。
6. **測試**：測試裡用 JWE 做的使用者 token，改用 `MiddlewareTesting` 的 `AccessTokenTestSigner` 簽 `subType: "user"` 的 at+jwt，並把該 signer 以 `callerTypes: [.user]` 放進 trust。

上線順序：各服務先以 1.3.0 + 信任設定部署（同時接受兩種 token）→ IdentityContext 改發 at+jwt → 等舊 JWE token 過期（≥ 其壽命）後各服務升 2.0 → 刪除 JWE 私鑰與 `MENDESKY_AUTH_*`。

升 2.0 之前，先在還跑 1.3 的服務上確認 `legacy-jwe-accepted` log 已經停止出現（最後一筆早於 JWE 的壽命，第一方 JWE 是 15 分鐘）。2.0 沒有這行 log（見第 4 點），只能在 1.3 上查；還有新的 `legacy-jwe-accepted` 就代表仍有人拿 JWE 進來，這時升 2.0 會讓他們 401。

---

## 授權：`PermissionMiddleware`（endpoint-level RBAC）

掛在 `BearerTokenAuthenticationMiddleware` 後面。對「有規則涵蓋」的路由：先讀 `Caller.current` 拿 `userId`（沒有呼叫者，例如前面沒掛 Bearer，就 `401`）→ 透過 `PermissionsProvider` 取得該 user 的權限 → 跟規則要求的權限做 **AND** 比對（exact string match）→ 放行或擋。

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

`HEAD` 請求會符合 `methods` 含 `GET` 的規則（`methods: nil` 的規則本來就符合所有 method）。

> ⚠️ **使用本套件的服務不可開啟 Hummingbird 的 `RouterOptions.caseInsensitive` 或 `.autoGenerateHeadEndpoints`**（兩者預設都是關的）。`PermissionRule` 與 `RouteAcceptance` 依請求路徑原樣（區分大小寫）比對；開了 `caseInsensitive`，大小寫不同的路徑（`/Quotations/1`）會到達 handler 卻不符合任何規則；開了 `autoGenerateHeadEndpoints`，`HEAD` 請求會被導到 `GET` handler（本套件只處理 `HEAD` 對 `GET` 規則的 method 比對）。

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
| 命中規則但沒有 `Caller.current`（前面沒有 Bearer）或呼叫者是 `.application` | `401` |
| provider（IAM 查詢）失敗 | `502`（fail-closed；用 502 而非 503，以區分「上游依賴故障」）|
| 缺所需權限 | `403` |
| 權限齊全 | 放行進 handler |

---

## 接線範例（以 OCServer 為例）

```swift
// (1) 信任設定：BearerTokenAuthenticationMiddleware() 從 MENDESKY_ACCESS_TOKEN_TRUST(_PATH) 載入（必填）

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
router.add(middleware: try PermissionMiddleware(rules: rules,              // 授權
                                                provider: provider))
router.add(middleware: LoggingMiddleware())
try api.registerHandlers(on: router, serverURL: URL(string: "/opportunity-context")!)
```

> `PermissionMiddleware` 必須排在 `BearerTokenAuthenticationMiddleware` 之後：它只讀 `Caller.current`，Bearer 在後或沒有 Bearer 時，命中規則的請求一律 `401`。
>
> `PermissionMiddleware.init(rules:provider:)` 標成 `throws` 只是為了相容既有的 `try` 呼叫；2.0 起它不讀環境變數、也不會 throw。

### 一次請求的流向

```
前端 ──HTTP──▶ CORS ─▶ BearerTokenAuth（驗證 at+jwt、驗 operatorId/applicationId、設定 Caller.current）─▶ PermissionMiddleware ─▶ handler
                                                                            │ 1. method/path 比對 rules → 算出本請求所需權限
                                                                            │ 2. 讀 Caller.current 拿 userId（沒有就 401）                       
                                                                            │ 3. provider 取該 user 權限（命中快取就不打 IAM）
                                                                            │ 4. AND 比對 → 放行 / 401 / 403 / 502
                                                                            ▼
                                                        provider 未命中 ──HTTP──▶ IAMContext GET /employee-access/permissions/{userId}
```

受保護請求必帶：`Authorization: Bearer <token>`（at+jwt）與 `operatorId: <id>`（`userId` 為 deprecated fallback）；`.application` 與 `.delegatedUser` 另須帶 `applicationId`，`.user` 可省略（Middleware 補上 `mendesky-first-party`）。各身分應帶的值見「呼叫者 header」。

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

`ProxyHeaderReceiverMiddleware` **一律**會收下 `applicationId`（不必列進 `presetKeys`；有列也不會收兩次）。`.application` / `.delegatedUser` 的請求由呼叫者自己帶 `applicationId`，不論 middleware 順序都收得到；`.user` 請求由 Bearer 補上的 `mendesky-first-party` 只有在 receiver 排在 Bearer **之後**才收得到——沒收到時，下游收到沒帶 `applicationId` 的 `.user` 請求也會自己補上，所以轉發不會因此失敗。

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
- **為什麼移除 JWE**：1.x 的 JWE（ECDH-ES）只有機密性、沒有簽發者認證——任何握有 recipient **公鑰**者都能做出一個合法的 token，而 recipient 私鑰又得複製到每個服務。2.0 只收 RS256 簽章的 at+jwt，各服務只需要發行者的公鑰。
- **粗粒度**：本層是 endpoint 級檢查（「能不能呼叫這個 endpoint」）；resource 級規則（「能不能改這一筆」）仍須在 handler 內做。
