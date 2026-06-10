# Middleware

**繁體中文** ｜ [English](README.en.md)

Mendesky 平台共用的 [Hummingbird 2.x](https://github.com/hummingbird-project/hummingbird) middleware 套件。這是一個 **library package**（非執行檔），給各個 context 服務（OpportunityContext、QuotingContext…）共用。

提供：

- **認證**：JWE bearer token 解密（`BearerTokenAuthenticationMiddleware`）
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
| `BearerTokenAuthenticationMiddleware` | server（`MiddlewareProtocol`）| 解密 JWE token、驗身分（你是誰）|
| `PermissionMiddleware` | server（`MiddlewareProtocol`）| endpoint 權限檢查（你能不能做）|
| `DynamicCORSMiddleware<Context>` | server（`RouterMiddleware`）| origin 白名單 CORS + preflight |
| `LoggingMiddleware` | server（`MiddlewareProtocol`）| debug-level 請求/回應 log |
| `ProxyHeaderReceiverMiddleware` | server（`MiddlewareProtocol`）| 把指定 inbound header 收進 `TaskLocal` |
| `AccessTokenMiddleware` | client（`ClientMiddleware`）| 把當前請求的 `Authorization` 轉發到 outbound 呼叫 |
| `ProxyHeaderSenderMiddleware` | client（`ClientMiddleware`）| 把 `SetHeaders` 收集到的 header 附到 outbound 呼叫 |

---

## 認證：`BearerTokenAuthenticationMiddleware`

解密 `Authorization: Bearer <JWE>` access token，並比對 `userId` header 防盜用。

金鑰從環境變數載入：

| 環境變數 | 必填 | 說明 |
|---|---|---|
| `MENDESKY_AUTH_RECIPIENT_JWK` 或 `..._JWK_PATH` | ✅ | 解密私鑰（JWK JSON / base64 或檔案路徑）|
| `MENDESKY_AUTH_SENDER_JWK` 或 `..._JWK_PATH` | — | 驗簽公鑰 |
| `MENDESKY_AUTH_PASSWORD` | — | JWK 密碼（base64）|

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
| 解密失敗 / token 過期 | `401` |
| 沒帶 `userId` header | `400` |
| `userId` header ≠ token 內 userId | `400`（防盜用）|
| 未預期錯誤 | `503` |

> 白名單用 `PathValidator`（見下方），符合的路徑會跳過認證；`OPTIONS` 一律跳過（給 CORS preflight）。

---

## 授權：`PermissionMiddleware`（endpoint-level RBAC）

掛在 `BearerTokenAuthenticationMiddleware` 後面。對「有規則涵蓋」的路由：解 token 拿 `userId` → 透過 `PermissionsProvider` 取得該 user 的權限 → 跟規則要求的權限做 **AND** 比對（exact string match）→ 放行或擋。

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
- `CachingPermissionsProvider(wrapping:ttl:)` — actor、per-userId、單調時鐘 TTL（預設 60s）、**只快取成功**、`invalidate(userId:)` / `invalidateAll()`。

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
let rules: [PermissionRule] = [
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/.+/total-assets")),
          methods: [.patch], requires: ["business:write"]),
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/.+")),
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

> `PermissionMiddleware` 另有 `init(rules:provider:)`（throws），會自己從 `MENDESKY_AUTH_*` 載入 verification，省去第 (1) 步。

### 一次請求的流向

```
前端 ──HTTP──▶ CORS ─▶ BearerTokenAuth（解密、驗 userId）─▶ PermissionMiddleware ─▶ handler
                                                              │ 1. method/path 比對 rules → 算出本請求所需權限
                                                              │ 2. 解 token 拿 userId
                                                              │ 3. provider 取該 user 權限（命中快取就不打 IAM）
                                                              │ 4. AND 比對 → 放行 / 401 / 403 / 502
                                                              ▼
                                          provider 未命中 ──HTTP──▶ IAMContext GET /employee-access/permissions/{userId}
```

受保護請求必帶：`Authorization: Bearer <JWE>` 與 `userId: <id>`（須等於 token 內 userId）。

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

---

## 設計筆記

- **`PermissionMiddleware` 不打 IAMContext**：它只呼叫注入的 `PermissionsProvider`（port）。真正的 HTTP client 由消費端提供——讓本套件保持零 IAM 依賴、可單獨編譯與測試（單元測試注入 fake provider，0 網路）。
- **IAM client 該放哪**：建議放在 IAMContext 的 client 產物 / 共用 client 套件（implement `PermissionsProvider`），而非塞進本套件——「誰提供 API，誰擁有 client」。
- **權限新鮮度**：IAMContext 投影為最終一致（grant/revoke 後 ~1–2s 才反映）；快取 TTL 與 `invalidate(userId:)` 是控制新鮮度的旋鈕。
- **粗粒度**：本層是 endpoint 級檢查（「能不能呼叫這個 endpoint」）；resource 級規則（「能不能改這一筆」）仍須在 handler 內做。
