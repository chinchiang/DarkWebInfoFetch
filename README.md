# DARK//WATCH — 暗網威脅情資監控 / Dark Web Threat Intel Feed

每 2 小時自動從 X(Twitter)上精選的暗網/資安威脅情資帳號抓取最新貼文,
並以中/英雙語互動網站呈現。
Automatically fetches the latest posts from curated dark-web threat-intel
accounts on X every 2 hours, and presents them on an interactive bilingual
(繁中/EN) website.

## 追蹤帳號 / Tracked accounts

| 分類 Category | 帳號 Account | 說明 |
|---|---|---|
| 高度推薦 Top pick | [@DailyDarkWeb](https://x.com/DailyDarkWeb) | 暗網資料外洩、勒索軟體攻擊、資料販售 |
| 高度推薦 Top pick | [@DarkWebInformer](https://x.com/DarkWebInformer) | 暗網/明網威脅情資、勒索軟體、市場動態與 IOC |
| 強力推薦 Strong | [@jms_dot_py](https://x.com/jms_dot_py) | Hunchly 作者,Tor 隱藏服務報告與 Onion 新發現 |
| 強力推薦 Strong | [@campuscodi](https://x.com/campuscodi) | 資深資安記者,暗網洩漏與重大資安事件 |
| 強力推薦 Strong | [@GossiTheDog](https://x.com/GossiTheDog) | 威脅情資專家,早期警告與地下趨勢 |
| 補充推薦 Extra | [@briankrebs](https://x.com/briankrebs) | 資安調查記者,暗網犯罪深度報導 |
| 補充推薦 Extra | [@vxunderground](https://x.com/vxunderground) | 惡意軟體、資料洩漏與地下論壇 |
| 補充推薦 Extra | [@Gi7w0rm](https://x.com/Gi7w0rm) | 惡意軟體、資料洩漏與地下論壇 |
| 補充推薦 Extra | [@MonThreat](https://x.com/MonThreat) | ThreatMon,中東與全球威脅情資 |

## 架構 / How it works

```
.github/workflows/fetch.yml   GitHub Actions cron(每 2 小時 / every 2 hours)
scripts/fetch_feed.py         抓取貼文 → data/feed.json(X API v2 或 Nitter RSS)
data/feed.json                情資資料(自動 commit 更新)
index.html                    互動網站(單一檔案,讀取 data/feed.json)
```

- **抓取來源 / Data source**:設定了 `X_BEARER_TOKEN` secret 時使用官方
  X API v2;否則退回公開 Nitter RSS 鏡像。兩者都失敗時保留既有資料。
- **資料合併 / Merge**:新舊貼文依 ID 去重,每帳號保留最近 30 則;
  首次成功抓取後會自動移除示範資料。
- **網站 / Site**:`index.html` 為單一自足檔案 —— 中/英切換、分類/主題/
  帳號過濾、關鍵字搜尋、每 10 分鐘自動重新載入資料。

## 設定 / Setup

1. **(建議 / Recommended)** 在 repo 的 *Settings → Secrets and variables →
   Actions* 新增 `X_BEARER_TOKEN`(X API v2 Bearer Token),抓取更穩定。
   沒有 token 時會使用 Nitter RSS 鏡像(可用性視鏡像站而定)。
2. **啟用排程 / Enable the schedule**:GitHub 的排程 workflow 只在
   **預設分支(main)** 上執行 —— 將本分支合併到 `main` 後,
   `fetch.yml` 會每 2 小時自動執行(也可在 Actions 頁面手動 *Run workflow*)。
3. **啟用網站 / Enable the site**:*Settings → Pages → Deploy from a branch*,
   選 `main` 分支、`/ (root)` 目錄,網站即為
   `https://<user>.github.io/DarkWebInfoFetch/`。

## 本地執行 / Run locally

```bash
python scripts/fetch_feed.py          # 抓取一次(可選:export X_BEARER_TOKEN=...)
python -m http.server 8000            # 然後開啟 http://localhost:8000
```

## 免責聲明 / Disclaimer

本專案僅彙整各帳號的公開貼文供資安預警參考,內容著作權屬原作者;
引用前請自行查證原始來源。
This project aggregates public posts for defensive threat-intelligence
awareness only; content belongs to the original authors.
