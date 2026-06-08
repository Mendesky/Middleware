<!-- BEGIN brain-link (managed by /link-brain) -->

## brain vault 整合

此專案已 link 到個人 wiki vault `~/brain`（slug: `mendesky-middleware`）。完整協議見 `~/brain/_schema/WIKI_SCHEMA.md` §11。

### 寫入規則（你唯一能改的位置）

- 唯一可寫路徑：`~/brain/raw/projects/mendesky-middleware/YYYY-MM-DD.md`
- 同一天 append 到同一檔，不另開新檔。
- 條目格式：
  ```
  ## [HH:MM] <topic>

  - bullet
  - bullet
  ```
- 何時值得寫：本 session 有「未來會想回頭看」的決策、bug 根因、API 變動、會議結論、踩到的非顯而易見的雷。**不要把所有 commit 訊息照抄一次**——那是 git log 的工作。
- Commit 寫入時：在 brain 那個 repo commit，prefix `[claude]` / `[codex]` / `[gemini]`，message 必須含 slug，例如：`[claude] log: mendesky-middleware YYYY-MM-DD session`。

### 讀取規則

- 可讀：`~/brain/wiki/` 任何頁、`~/brain/_meta/index.md`。需要找既有研究、概念、過往決策時，先看 index。
- 不可讀：其他專案的 `raw/projects/<other>/`（用 wiki 頁取得跨專案知識，不直接挖別人的原始筆記）。

### 絕對禁止

- 寫入 `~/brain/wiki/`、`~/brain/_meta/`、`~/brain/_schema/`、其他專案的 raw。
- 從本專案觸發 brain ingest——ingest 由 user 在 brain 那邊主動跑。
- 刪改 `raw/projects/mendesky-middleware/` 內既有檔案——raw 是 immutable，新進度 append 到當日檔即可。

<!-- END brain-link -->