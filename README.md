# DARK//WATCH — 暗網威脅情資監控 / Dark Web Threat Intel Feed

每日約 05:00 與 13:00(台北時間,UTC+8)自動從 X(Twitter)上精選的
暗網/資安威脅情資帳號抓取最新貼文,並以中/英雙語互動網站呈現。
Automatically fetches the latest posts from curated dark-web threat-intel
accounts on X twice daily around 05:00 and 13:00 Taipei time (UTC+8), and
presents them on an interactive bilingual (繁中/EN) website.

## 追蹤帳號 / Tracked accounts(13,以暗網為主 dark-web-focused)

| 分類 Category | 帳號 Accounts |
|---|---|
| 高度推薦(暗網專門)Top picks | @DailyDarkWeb, @DarkWebInformer |
| 強力推薦(暗網/地下威脅情報)Strong | @jms_dot_py, @campuscodi, @GossiTheDog, @GroupIB_TI, @CTI_Alerts |
| 補充推薦 Extra | @briankrebs, @vxunderground, @Gi7w0rm, @MonThreat |
| 中文情資 Chinese | @twcertcc, @TeamT5_Official |

## 架構 / How it works

```
.github/workflows/fetch.yml   GitHub Actions cron(每日 04:23 / 12:30 UTC+8 觸發,
                              預留 GitHub 排程延遲,約 05:00 / 13:00 完成更新)
scripts/fetch_feed.py         抓取貼文 → data/feed.json(X API v2 或 Nitter RSS)
data/feed.json                情資資料(自動 commit 更新)
index.html                    主頁:最近 7 天的新貼文 + 國別警示列
archive.html                  歷史頁:7 天以前的貼文
assets/style.css, app.js      兩頁共用的樣式與程式
```

- **抓取來源 / Data source**:設定了 `X_BEARER_TOKEN` secret 時使用官方
  X API v2(需 Basic 方案以上);否則退回公開 Nitter RSS 鏡像。
  @GossiTheDog 與 @campuscodi 在 Nitter 全數失敗時,改抓其 Mastodon
  公開 RSS(兩位作者會同步發文)。全部失敗時保留既有資料。
- **資料合併 / Merge**:新舊貼文依 ID 去重,每帳號保留最近 60 則;
  首次成功抓取後會自動移除示範資料。
- **網站 / Site**:中/英切換、分類/主題/帳號過濾、每 10 分鐘自動重新載入。
  主頁(`index.html`)顯示最近 7 天的新貼文,較舊貼文移至歷史頁
  (`archive.html`);**關鍵字搜尋永遠涵蓋全部貼文**(不受 7 天限制)。
- **國別警示 / Country alert**:警示列會掃描所有貼文,發現與警示國別
  (預設台灣,可下拉選擇並記住偏好)相關的內容時高亮示警,可一鍵
  查看相關貼文。
- **雙語內容 / Bilingual content**:抓取時自動將貼文機器翻譯為繁體中文
  並快取於 `feed.json`(`text_zh`,增量翻譯、每次最多 80 則)。介面選
  「中文」顯示譯文(標示「機器翻譯」,每則可切回原文),選「EN」顯示
  英文原文。

## 設定 / Setup

1. **(建議 / Recommended)** 在 repo 的 *Settings → Secrets and variables →
   Actions* 新增 `X_BEARER_TOKEN`(X API v2 Bearer Token),抓取更穩定。
   沒有 token 時會使用 Nitter RSS 鏡像(可用性視鏡像站而定)。
2. **啟用排程 / Enable the schedule**:GitHub 的排程 workflow 只在
   **預設分支(main)** 上執行 —— 將本分支合併到 `main` 後,
   `fetch.yml` 會於每日約 05:00 與 13:00(UTC+8)自動執行
   (也可在 Actions 頁面手動 *Run workflow*)。
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
