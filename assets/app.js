"use strict";

/* page mode: "recent" (index.html, last 7 days) or "archive" (archive.html) */
const MODE = document.body.dataset.mode || "recent";
const WEEK_MS = 7 * 86400 * 1000;

/* ================= account metadata (bilingual) ================= */
const ACCOUNT_META = {
  DailyDarkWeb: {
    name: "Daily Dark Web", category: "core",
    desc: {
      zh: "專門追蹤暗網資料外洩、勒索軟體攻擊與資料販售,更新頻繁,入門首選。",
      en: "Tracks dark web data leaks, ransomware attacks and data sales. Frequent updates — a top starting point."
    }
  },
  DarkWebInformer: {
    name: "Dark Web Informer", category: "core",
    desc: {
      zh: "提供暗網與明網威脅情資:勒索軟體、資料外洩、暗網市場動態與 IOC。",
      en: "Dark & clear web threat intel: ransomware, breaches, dark web market activity and IOCs."
    }
  },
  ransomwatcher: {
    name: "RansomWatcher", category: "core",
    desc: {
      zh: "勒索軟體洩密網站自動監控機器人:受害者名單一更新立即發布,純情資流。",
      en: "Automated ransomware leak-site monitor: posts the moment victim lists update. Pure intel feed."
    }
  },
  tmransommonitor: {
    name: "ThreatMon Ransomware Monitor", category: "core",
    desc: {
      zh: "ThreatMon 勒索軟體監控機器人,自動追蹤各勒索軟體家族洩密網站的受害者公告。",
      en: "ThreatMon's ransomware monitoring bot; auto-tracks victim announcements across leak sites."
    }
  },
  jms_dot_py: {
    name: "Justin Seitz", category: "strong",
    desc: {
      zh: "Hunchly 工具作者,定期分享 Tor 隱藏服務報告與新發現的 Onion 服務。",
      en: "Author of Hunchly; shares Tor hidden-service reports and newly discovered onion services."
    }
  },
  campuscodi: {
    name: "Catalin Cimpanu", category: "strong",
    desc: {
      zh: "資深資安記者,報導暗網洩漏、勒索軟體與重大資安事件。",
      en: "Veteran security journalist covering dark web leaks, ransomware and major incidents."
    }
  },
  GossiTheDog: {
    name: "Kevin Beaumont", category: "strong",
    desc: {
      zh: "威脅情資專家,常分享早期警告、勒索軟體與地下趨勢。",
      en: "Threat intel expert; early warnings, ransomware and underground trends."
    }
  },
  GroupIB_TI: {
    name: "Group-IB TI", category: "strong",
    desc: {
      zh: "Group-IB 官方威脅情報,集團級暗網與網路犯罪追蹤。",
      en: "Group-IB threat intelligence; corporate-grade dark web and cybercrime tracking."
    }
  },
  CTI_Alerts: {
    name: "CTI Alerts", category: "strong",
    desc: {
      zh: "持續監控 IOC 與攻擊者 TTP 的威脅情報警示。",
      en: "Continuous threat-intel alerts monitoring IOCs and attacker TTPs."
    }
  },
  briankrebs: {
    name: "Brian Krebs", category: "extra",
    desc: {
      zh: "知名資安調查記者,深度報導暗網犯罪與資安事件。",
      en: "Renowned investigative journalist; deep reporting on dark web crime and security incidents."
    }
  },
  vxunderground: {
    name: "vx-underground", category: "extra",
    desc: {
      zh: "惡意軟體研究社群,分享惡意軟體、資料洩漏與地下論壇動態。",
      en: "Malware research collective; malware, data leaks and underground forum activity."
    }
  },
  Gi7w0rm: {
    name: "Gi7w0rm", category: "extra",
    desc: {
      zh: "獨立研究員,分享惡意軟體、資料洩漏與地下論壇情資。",
      en: "Independent researcher; malware, data leaks and underground forum findings."
    }
  },
  MonThreat: {
    name: "ThreatMon", category: "extra",
    desc: {
      zh: "ThreatMon 官方帳號,中東與全球威脅情資,涵蓋暗網情報追蹤。",
      en: "ThreatMon — Middle East & global threat intelligence, including dark web tracking."
    }
  },
  twcertcc: {
    name: "TWCERT/CC", category: "zhtw",
    desc: {
      zh: "台灣電腦網路危機處理暨協調中心官方帳號,中文資安警訊、漏洞通報與外洩情資。",
      en: "Taiwan's national CERT: Chinese-language security alerts, vulnerability advisories and breach intel."
    }
  },
  TeamT5_Official: {
    name: "TeamT5 杜浦數位安全", category: "zhtw",
    desc: {
      zh: "台灣威脅情資公司,專精 APT 與地下活動研究,亞太區威脅研究領先團隊。",
      en: "Taiwan threat-intel firm specializing in APT and underground research; a leading APAC team."
    }
  }
};

const CATEGORIES = {
  core:   { color: "var(--red)",     chip: "chip-red" },
  strong: { color: "var(--blue)",    chip: "chip-blue" },
  extra:  { color: "var(--orange)",  chip: "chip-orange" },
  zhtw:   { color: "var(--magenta)", chip: "chip-magenta" }
};
const CATEGORY_ORDER = ["core", "strong", "extra", "zhtw"];

const TAGS = {
  ransomware: { color: "var(--red)",     chip: "chip-red" },
  breach:     { color: "var(--orange)",  chip: "chip-orange" },
  market:     { color: "var(--purple)",  chip: "chip-purple" },
  malware:    { color: "var(--magenta)", chip: "chip-magenta" },
  vuln:       { color: "var(--blue)",    chip: "chip-blue" },
  darkweb:    { color: "var(--mint)",    chip: "chip-mint" },
  other:      { color: "var(--muted)",   chip: "chip-plain" }
};

/* security-signal scoring, mirrors scripts/fetch_feed.py; the fetcher
   stores `score` in feed.json — this is the client-side fallback */
const SIGNAL_RULES = [
  [3, /\bcve-\d{4}-\d+|\biocs?\b|ransom|data (leak|breach)|victim|\.onion\b|zero.?day|\b0.?day\b/i],
  [2, /exploit|malware|stealer|botnet|breach|leak(ed|s|age)?\b|dark ?web|darknet|threat actor|credential|infostealer/i],
  [1, /vulnerab|phishing|hack(ed|er|ing)|securit|infosec|\bapt\b|threat intel|patch(es|ed)?\b|backdoor|\btor\b|osint|\bddos\b|c2\b/i]
];
function postScore(p) {
  if (typeof p.score === "number") return p.score;
  if (p._score == null) {
    p._score = SIGNAL_RULES.reduce((s, r) => s + (r[1].test(p.text || "") ? r[0] : 0), 0);
  }
  return p._score;
}
const isPriority = p => postScore(p) >= 3;
const isNoise = p => postScore(p) === 0;

/* ================= comic mascots (inline SVG, macaron palette) ================= */
/* chibi hooded hacker with laptop — the site mascot */
const MASCOT_HERO = `
<svg viewBox="0 0 220 214" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="DARK//WATCH mascot">
  <ellipse cx="110" cy="202" rx="64" ry="9" fill="rgba(12,8,26,.45)"/>
  <path d="M60 152 Q60 110 110 110 Q160 110 160 152 L160 180 Q160 190 150 190 L70 190 Q60 190 60 180 Z" fill="#4a4173"/>
  <path d="M68 54 L58 20 L94 38 Z" fill="#4a4173"/>
  <path d="M152 54 L162 20 L126 38 Z" fill="#4a4173"/>
  <path d="M70 48 L64 28 L85 39 Z" fill="#f7a8bc"/>
  <path d="M150 48 L156 28 L135 39 Z" fill="#f7a8bc"/>
  <circle cx="110" cy="80" r="52" fill="#4a4173"/>
  <circle cx="110" cy="82" r="38" fill="#241f38" stroke="#c8b5f4" stroke-width="3"/>
  <circle cx="110" cy="84" r="32" fill="#ffe9df"/>
  <ellipse cx="97" cy="82" rx="5" ry="7" fill="#3b3354"/>
  <ellipse cx="123" cy="82" rx="5" ry="7" fill="#3b3354"/>
  <circle cx="99" cy="79" r="1.8" fill="#fff"/>
  <circle cx="125" cy="79" r="1.8" fill="#fff"/>
  <ellipse cx="87" cy="94" rx="6" ry="3.5" fill="#f7a8bc" opacity=".85"/>
  <ellipse cx="133" cy="94" rx="6" ry="3.5" fill="#f7a8bc" opacity=".85"/>
  <path d="M104 95 Q110 101 116 95" stroke="#3b3354" stroke-width="2.5" fill="none" stroke-linecap="round"/>
  <rect x="70" y="144" width="80" height="36" rx="7" fill="#c8b5f4"/>
  <rect x="77" y="150" width="66" height="24" rx="4" fill="#241f38"/>
  <text x="110" y="166" text-anchor="middle" font-family="monospace" font-size="11" fill="#a9e8cd">01&#183;10</text>
  <circle cx="72" cy="164" r="8" fill="#ffe9df"/>
  <circle cx="148" cy="164" r="8" fill="#ffe9df"/>
  <circle cx="34" cy="64" r="4" fill="#a9e8cd"/>
  <circle cx="188" cy="44" r="3" fill="#f7a8bc"/>
  <path d="M186 112 l4 9 9 4 -9 4 -4 9 -4 -9 -9 -4 9 -4 Z" fill="#ffcda6"/>
  <circle cx="26" cy="130" r="2.5" fill="#a8d8f8"/>
</svg>`;

/* sleeping ghost — empty state */
const GHOST_SVG = `
<svg viewBox="0 0 150 122" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <ellipse cx="72" cy="114" rx="40" ry="6" fill="rgba(12,8,26,.45)"/>
  <path d="M40 104 V62 Q40 28 72 28 Q104 28 104 62 V104 L94 95 L83 104 L72 95 L61 104 L50 95 Z"
        fill="#342d55" stroke="#c8b5f4" stroke-width="2.5" stroke-linejoin="round"/>
  <path d="M58 62 Q62 66.5 66 62" stroke="#f3eefb" stroke-width="2.2" fill="none" stroke-linecap="round"/>
  <path d="M78 62 Q82 66.5 86 62" stroke="#f3eefb" stroke-width="2.2" fill="none" stroke-linecap="round"/>
  <ellipse cx="55" cy="72" rx="5" ry="3" fill="#f7a8bc" opacity=".8"/>
  <ellipse cx="89" cy="72" rx="5" ry="3" fill="#f7a8bc" opacity=".8"/>
  <path d="M68 76 Q72 79 76 76" stroke="#f3eefb" stroke-width="2" fill="none" stroke-linecap="round"/>
  <text x="112" y="34" font-family="monospace" font-size="13" fill="#a9e8cd">z</text>
  <text x="120" y="24" font-family="monospace" font-size="16" fill="#a9e8cd">Z</text>
  <circle cx="30" cy="40" r="3" fill="#ffcda6"/>
</svg>`;

/* alert bar faces */
const FACE_ALERT = `
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="8.2" cy="9.5" r="2.1" fill="currentColor"/>
  <circle cx="15.8" cy="9.5" r="2.1" fill="currentColor"/>
  <ellipse cx="12" cy="16.2" rx="2.7" ry="3.2" fill="currentColor"/>
  <path d="M20.5 4.5 q1.6 1.8 .6 4" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/>
</svg>`;
const FACE_CALM = `
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
  <path d="M5.5 10 q2.2 2.6 4.4 0"/>
  <path d="M14.1 10 q2.2 2.6 4.4 0"/>
  <path d="M9 15.5 q3 3 6 0"/>
</svg>`;

/* ================= watch countries (alert bar) ================= */
const COUNTRIES = {
  taiwan:    { zh: "台灣",   en: "Taiwan",
               rx: [/taiwan(ese)?/i, /台灣|臺灣|台湾/, /\btsmc\b/i, /中華民國/, /formosa/i,
                    /\.tw\b/i,                                        /* .tw domains */
                    /taipei|kaohsiung|taichung|tainan|hsinchu/i,      /* major cities */
                    /台北|臺北|高雄|台中|臺中|台南|臺南|新竹/,
                    /foxconn|mediatek|\basus\b|\bacer\b/i,            /* flagship companies */
                    /鴻海|聯發科|台積電|華碩|宏碁/] },
  japan:     { zh: "日本",   en: "Japan",
               rx: [/japan(ese)?/i, /日本/, /tokyo/i] },
  korea:     { zh: "韓國",   en: "Korea",
               rx: [/korean?/i, /韓國|南韓|한국/, /seoul/i] },
  china:     { zh: "中國",   en: "China",
               rx: [/\bchina\b|chinese/i, /中國|中国/, /beijing|shanghai/i, /\bPRC\b/] },
  hongkong:  { zh: "香港",   en: "Hong Kong",
               rx: [/hong\s?kong/i, /香港/, /\bHK\b/] },
  singapore: { zh: "新加坡", en: "Singapore",
               rx: [/singapore(an)?/i, /新加坡/] },
  usa:       { zh: "美國",   en: "USA",
               rx: [/united states|u\.s\.a?|american?\b/i, /\bUSA?\b/, /美國/] },
  uk:        { zh: "英國",   en: "UK",
               rx: [/united kingdom|britain|british/i, /\bUK\b/, /英國/] },
  germany:   { zh: "德國",   en: "Germany",
               rx: [/germany?|german\b/i, /德國/] },
  australia: { zh: "澳洲",   en: "Australia",
               rx: [/australian?/i, /澳洲|澳大利亞/] }
};

/* ================= i18n ================= */
const I18N = {
  zh: {
    docTitle: "DARKWATCH — 暗網威脅情資監控台",
    docTitleArchive: "DARKWATCH — 歷史情資",
    eyebrow: "DARK WEB · THREAT INTELLIGENCE · 每日 05:00 / 13:00 更新",
    titleHtml: '暗網<span class="hl-a">威脅情資</span>即時<span class="hl-b">監控台</span>',
    tagline: "彙整 15 個以暗網為主的精選 X(Twitter)情資帳號:暗網資料外洩、勒索軟體洩密網站、地下市場與惡意軟體動態,每日約 05:00 與 13:00(UTC+8)自動抓取更新。",
    updated: "最後更新", source: "資料來源", cadence: "每日 05:00 / 13:00 自動抓取",
    postsUnit: "則情資", newPosts: "本次新增",
    sampleNotice: "目前顯示為示範資料 — 首次排程抓取完成後,將自動替換為各帳號的即時貼文。",
    searchPlaceholder: "搜尋全部貼文:關鍵字、帳號、CVE…",
    catLabel: "分類", tagLabel: "主題",
    catAll: "全部", catCore: "高度推薦", catStrong: "強力推薦", catExtra: "補充推薦", catZh: "中文情資",
    tagNames: { ransomware: "勒索軟體", breach: "資料外洩", market: "暗網市場", malware: "惡意軟體", vuln: "漏洞/利用", darkweb: "Onion/Tor", other: "其他" },
    sortLabel: "排序", sortPriority: "⚡ 優先", sortLatest: "最新",
    priorityBadge: "⚡ 高優先",
    noiseChip: "一般貼文(非資安)",
    accounts: "追蹤帳號",
    feedTitle: "即時情資流・近 7 天", feedTitleArchive: "歷史情資流・7 天以前",
    navRecent: "最新情資", navArchive: "歷史情資",
    watchLabel: "警示國別",
    kwLabel: "★ 關注關鍵字",
    kwPlaceholder: "輸入關鍵字後按 Enter 加入…",
    kwRemove: "移除",
    alertHit: (name, n) => `警示:偵測到 ${n} 則與「${name}」相關的情資 — 點擊只看相關貼文`,
    alertNone: name => `目前沒有與「${name}」相關的情資`,
    alertView: "只看相關貼文", alertClear: "✕ 清除篩選,顯示全部",
    watchTag: name => `${name}相關`,
    postsCount: n => `${n} 則`,
    openOnX: "在 X 上查看 ↗",
    openSource: "查看來源 ↗",
    mtNote: "機器翻譯",
    showOrig: "看原文", showTrans: "看譯文",
    empty: "沒有符合條件的情資 — 請調整過濾條件。",
    emptyArchive: "還沒有 7 天以前的歷史貼文。",
    sources: { sample: "示範資料", x_api: "X API v2", nitter: "Nitter RSS", x_api_stale: "X API(快取)", nitter_stale: "Nitter RSS(快取)" },
    ago: { now: "剛剛", m: n => `${n} 分鐘前`, h: n => `${n} 小時前`, d: n => `${n} 天前` },
    footCadence: "GitHub Actions 每日 05:00 / 13:00(UTC+8)自動抓取",
    footSource: "資料來自各帳號公開貼文,著作權屬原作者",
    footDisclaimer: "本站為情資彙整工具,內容由來源帳號自動抓取,不代表本站立場;引用前請自行查證原始來源。"
  },
  en: {
    docTitle: "DARKWATCH — Dark Web Threat Intel Console",
    docTitleArchive: "DARKWATCH — Threat Intel Archive",
    eyebrow: "DARK WEB · THREAT INTELLIGENCE · REFRESHED DAILY AT 05:00 & 13:00",
    titleHtml: 'Dark Web <span class="hl-a">Threat Intel</span>, <span class="hl-b">Live Console</span>',
    tagline: "Aggregates 15 curated, dark-web-focused X (Twitter) accounts: dark web data leaks, ransomware leak sites, underground markets and malware activity — automatically fetched twice daily around 05:00 & 13:00 (UTC+8).",
    updated: "Updated", source: "Source", cadence: "Auto-fetch 05:00 & 13:00",
    postsUnit: "posts", newPosts: "new this update",
    sampleNotice: "Showing sample data — it will be replaced with live posts after the first scheduled fetch completes.",
    searchPlaceholder: "Search all posts: keywords, accounts, CVEs…",
    catLabel: "Category", tagLabel: "Topic",
    catAll: "All", catCore: "Top picks", catStrong: "Strong", catExtra: "Extra", catZh: "Chinese",
    tagNames: { ransomware: "Ransomware", breach: "Data breach", market: "Dark market", malware: "Malware", vuln: "Vuln/Exploit", darkweb: "Onion/Tor", other: "Other" },
    sortLabel: "Sort", sortPriority: "⚡ Priority", sortLatest: "Latest",
    priorityBadge: "⚡ PRIORITY",
    noiseChip: "Non-security posts",
    accounts: "Tracked accounts",
    feedTitle: "Live intel feed · last 7 days", feedTitleArchive: "Archive feed · older than 7 days",
    navRecent: "Latest", navArchive: "Archive",
    watchLabel: "Watch country",
    kwLabel: "★ Watch keywords",
    kwPlaceholder: "Type a keyword and press Enter…",
    kwRemove: "Remove",
    alertHit: (name, n) => `Alert: ${n} post${n > 1 ? "s" : ""} matching ${name} detected — click to view only those`,
    alertNone: name => `No intel matching ${name} right now`,
    alertView: "Only matches", alertClear: "✕ Clear filter, show all",
    watchTag: name => `${name}-related`,
    postsCount: n => `${n} posts`,
    openOnX: "Open on X ↗",
    openSource: "View source ↗",
    mtNote: "machine translated",
    showOrig: "Original", showTrans: "Translation",
    empty: "No intel matches the current filters — try adjusting them.",
    emptyArchive: "No posts older than 7 days yet.",
    sources: { sample: "Sample data", x_api: "X API v2", nitter: "Nitter RSS", x_api_stale: "X API (cached)", nitter_stale: "Nitter RSS (cached)" },
    ago: { now: "just now", m: n => `${n}m ago`, h: n => `${n}h ago`, d: n => `${n}d ago` },
    footCadence: "auto-fetched by GitHub Actions daily at 05:00 & 13:00 (UTC+8)",
    footSource: "content belongs to the original authors",
    footDisclaimer: "This site is an aggregation tool; posts are fetched automatically from the source accounts and do not represent this site's views. Verify with the original source before citing."
  }
};

/* ===== seed data start (replaced by data/feed.json at runtime) ===== */
const SEED = {
  generated_at: "2026-07-11T00:00:00Z",
  source: "sample",
  posts: [
    { id: "s1", handle: "DailyDarkWeb", name: "Daily Dark Web", sample: true,
      text: "[Sample 示範] Ransomware victim claim placeholder — live posts from @DailyDarkWeb will appear here after the first scheduled fetch.",
      url: "https://x.com/DailyDarkWeb", created_at: "2026-07-10T22:10:00Z", tags: ["ransomware"] },
    { id: "s2", handle: "DarkWebInformer", name: "Dark Web Informer", sample: true,
      text: "[Sample 示範] Data breach / leak alert placeholder — IOC and dark web market updates from @DarkWebInformer will appear here.",
      url: "https://x.com/DarkWebInformer", created_at: "2026-07-10T21:05:00Z", tags: ["breach", "market"] },
    { id: "s3", handle: "jms_dot_py", name: "Justin Seitz", sample: true,
      text: "[Sample 示範] Tor hidden service report placeholder — new onion service discoveries from @jms_dot_py will appear here.",
      url: "https://x.com/jms_dot_py", created_at: "2026-07-10T19:40:00Z", tags: ["other"] },
    { id: "s4", handle: "campuscodi", name: "Catalin Cimpanu", sample: true,
      text: "[Sample 示範] Security journalism placeholder — dark web leak and ransomware reporting from @campuscodi will appear here.",
      url: "https://x.com/campuscodi", created_at: "2026-07-10T18:20:00Z", tags: ["breach"] },
    { id: "s5", handle: "GossiTheDog", name: "Kevin Beaumont", sample: true,
      text: "[Sample 示範] Early warning placeholder — vulnerability and exploitation alerts from @GossiTheDog will appear here. CVE-0000-00000",
      url: "https://x.com/GossiTheDog", created_at: "2026-07-10T16:55:00Z", tags: ["vuln"] },
    { id: "s6", handle: "briankrebs", name: "Brian Krebs", sample: true,
      text: "[Sample 示範] Investigative reporting placeholder — dark web crime coverage from @briankrebs will appear here.",
      url: "https://x.com/briankrebs", created_at: "2026-07-10T15:30:00Z", tags: ["market"] },
    { id: "s7", handle: "vxunderground", name: "vx-underground", sample: true,
      text: "[Sample 示範] Malware research placeholder — sample analysis and underground forum notes from @vxunderground will appear here.",
      url: "https://x.com/vxunderground", created_at: "2026-07-10T14:00:00Z", tags: ["malware"] },
    { id: "s8", handle: "Gi7w0rm", name: "Gi7w0rm", sample: true,
      text: "[Sample 示範] Researcher notes placeholder — malware and data leak findings from @Gi7w0rm will appear here.",
      url: "https://x.com/Gi7w0rm", created_at: "2026-07-10T12:45:00Z", tags: ["malware", "breach"] },
    { id: "s9", handle: "MonThreat", name: "ThreatMon", sample: true,
      text: "[Sample 示範] Threat intel placeholder — Middle East & global dark web tracking from @MonThreat will appear here.",
      url: "https://x.com/MonThreat", created_at: "2026-07-10T11:15:00Z", tags: ["other"] }
  ]
};
/* ===== seed data end ===== */

/* ================= state ================= */
function readPref(key) {
  try { return localStorage.getItem(key); } catch (e) { return null; }
}
function savePref(key, val) {
  try { localStorage.setItem(key, val); } catch (e) {}
}
/* first visit: default to the browser language; afterwards the saved choice wins */
const browserLang = ((navigator.language || navigator.userLanguage || "zh")
  .toLowerCase().startsWith("zh")) ? "zh" : "en";
function readKeywords() {
  try {
    const arr = JSON.parse(readPref("dw-keywords") || "[]");
    return Array.isArray(arr) ? arr.filter(k => typeof k === "string" && k.trim()).slice(0, 20) : [];
  } catch (e) { return []; }
}
const state = {
  lang: readPref("dw-lang") || browserLang,
  watch: COUNTRIES[readPref("dw-watch")] ? readPref("dw-watch") : "taiwan",
  keywords: readKeywords(),  /* user-defined watch keywords */
  watchOnly: false,
  sort: readPref("dw-sort") === "latest" ? "latest" : "priority",
  showNoise: false,     /* score-0 posts (coffee, music…) hidden by default */
  showOrig: new Set(),  /* post ids temporarily showing the original text */
  q: "",
  cat: "all",
  tags: new Set(),
  account: null,
  data: SEED
};
const $ = id => document.getElementById(id);
const t = () => I18N[state.lang];

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function linkify(escaped) {
  return escaped.replace(/https?:\/\/[^\s<]+/g, u => `<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`);
}
function timeAgo(isoStr) {
  const then = Date.parse(isoStr);
  if (isNaN(then)) return isoStr || "";
  const s = Math.max(0, (Date.now() - then) / 1000);
  const ago = t().ago;
  if (s < 60) return ago.now;
  if (s < 3600) return ago.m(Math.floor(s / 60));
  if (s < 86400) return ago.h(Math.floor(s / 3600));
  return ago.d(Math.floor(s / 86400));
}
function fmtUtc(isoStr) {
  const d = new Date(isoStr);
  if (isNaN(d)) return "—";
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}
/* viewer-local time with an explicit UTC-offset label, e.g. "2026-07-18 05:11 (UTC+8)" */
function fmtLocal(isoStr) {
  const d = new Date(isoStr);
  if (isNaN(d)) return "—";
  const pad = n => String(n).padStart(2, "0");
  const off = -d.getTimezoneOffset() / 60;
  const offLabel = "UTC" + (off >= 0 ? "+" : "") + (Number.isInteger(off) ? off : off.toFixed(1));
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())} (${offLabel})`;
}

/* ================= filtering ================= */
function isRecent(p) {
  const ts = Date.parse(p.created_at);
  return isNaN(ts) ? true : (Date.now() - ts) <= WEEK_MS;
}
function matchCountry(p) {
  const c = COUNTRIES[state.watch];
  return c ? c.rx.some(r => r.test(p.text || "")) : false;
}
function matchedKeywords(p) {
  if (!state.keywords.length) return [];
  const hay = ((p.text || "") + " " + (p.text_zh || "")).toLowerCase();
  return state.keywords.filter(k => hay.includes(k.toLowerCase()));
}
/* a post is "watched" if it matches the country rules OR any user keyword */
function matchWatch(p) {
  return matchCountry(p) || matchedKeywords(p).length > 0;
}
function visiblePosts() {
  const q = state.q.trim().toLowerCase();
  return (state.data.posts || []).filter(p => {
    const meta = ACCOUNT_META[p.handle];
    if (state.cat !== "all" && (!meta || meta.category !== state.cat)) return false;
    if (state.account && p.handle !== state.account) return false;
    if (state.tags.size && !(p.tags || []).some(tag => state.tags.has(tag))) return false;
    if (q && !(p.text + " " + p.handle + " " + (p.name || "")).toLowerCase().includes(q)) return false;
    if (state.watchOnly && !matchWatch(p)) return false;
    // hide non-security chatter unless toggled on; search still covers it
    if (!state.showNoise && !q && isNoise(p)) return false;
    // The 7-day window only applies when browsing: searching and the
    // alert view always cover ALL posts.
    if (!q && !state.watchOnly) {
      if (MODE === "archive" ? isRecent(p) : !isRecent(p)) return false;
    }
    return true;
  });
}

/* ================= rendering ================= */
function renderStatic() {
  const L = t();
  document.documentElement.lang = state.lang === "zh" ? "zh-Hant" : "en";
  document.title = MODE === "archive" ? L.docTitleArchive : L.docTitle;
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const val = L[el.dataset.i18n];
    if (typeof val === "string") el.textContent = val;
  });
  $("hero-title").innerHTML = L.titleHtml;
  $("search").placeholder = L.searchPlaceholder;
  $("lang-zh").setAttribute("aria-pressed", String(state.lang === "zh"));
  $("lang-en").setAttribute("aria-pressed", String(state.lang === "en"));
}

function renderAlert() {
  const L = t();
  const country = COUNTRIES[state.watch];
  const name = country[state.lang] + (state.keywords.length ? " / ★" : "");
  const matches = (state.data.posts || []).filter(matchWatch);
  const bar = $("alert-bar");
  bar.hidden = false;
  bar.classList.toggle("alert-hot", matches.length > 0);
  const clickable = matches.length > 0 || state.watchOnly;
  bar.classList.toggle("alert-clickable", clickable);
  bar.setAttribute("role", clickable ? "button" : "status");
  if (clickable) bar.setAttribute("tabindex", "0");
  else bar.removeAttribute("tabindex");
  $("alert-ico").innerHTML = matches.length ? FACE_ALERT : FACE_CALM;
  $("alert-text").textContent = matches.length
    ? L.alertHit(name, matches.length)
    : L.alertNone(name);
  const btn = $("alert-view");
  btn.hidden = !matches.length && !state.watchOnly;
  btn.textContent = state.watchOnly ? L.alertClear : L.alertView;
  btn.setAttribute("aria-pressed", String(state.watchOnly));
  const sel = $("watch-country");
  sel.innerHTML = Object.entries(COUNTRIES).map(([key, c]) =>
    `<option value="${key}"${key === state.watch ? " selected" : ""}>${escapeHtml(c[state.lang])}</option>`
  ).join("");
  $("kw-chips").innerHTML = state.keywords.map(k =>
    `<button class="kw-chip" data-kw-del="${escapeHtml(k)}" title="${escapeHtml(L.kwRemove)}">` +
    `★ ${escapeHtml(k)} <span class="x">×</span></button>`
  ).join("");
  $("kw-input").placeholder = L.kwPlaceholder;
}

function renderNav() {
  const L = t();
  const posts = state.data.posts || [];
  const recent = posts.filter(isRecent).length;
  $("tab-recent").textContent = `${L.navRecent} · ${recent}`;
  $("tab-archive").textContent = `${L.navArchive} · ${posts.length - recent}`;
  $("tab-recent").classList.toggle("active", MODE !== "archive");
  $("tab-archive").classList.toggle("active", MODE === "archive");
  if (MODE === "archive") $("tab-archive").setAttribute("aria-current", "page");
  else $("tab-recent").setAttribute("aria-current", "page");
}

function chipHtml(id, cls, label, count, pressed) {
  return `<button class="chip ${cls}" data-chip="${id}" aria-pressed="${pressed}">` +
    `${escapeHtml(label)}${count != null ? ` <span class="n">${count}</span>` : ""}</button>`;
}

function renderChips() {
  const L = t();
  const posts = state.data.posts || [];

  const catCounts = { core: 0, strong: 0, extra: 0, zhtw: 0 };
  posts.forEach(p => {
    const m = ACCOUNT_META[p.handle];
    if (m) catCounts[m.category]++;
  });
  const catNames = { all: L.catAll, core: L.catCore, strong: L.catStrong, extra: L.catExtra, zhtw: L.catZh };
  let html = `<span class="chip-label">${escapeHtml(L.catLabel)}</span>`;
  html += chipHtml("cat:all", "chip-plain", catNames.all, posts.length, state.cat === "all");
  for (const c of CATEGORY_ORDER) {
    html += chipHtml("cat:" + c, CATEGORIES[c].chip, catNames[c], catCounts[c], state.cat === c);
  }
  $("cat-chips").innerHTML = html;

  const tagCounts = {};
  posts.forEach(p => (p.tags || []).forEach(tag => { tagCounts[tag] = (tagCounts[tag] || 0) + 1; }));
  let thtml = `<span class="chip-label">${escapeHtml(L.tagLabel)}</span>`;
  for (const tag of Object.keys(TAGS)) {
    if (!tagCounts[tag]) continue;
    thtml += chipHtml("tag:" + tag, TAGS[tag].chip, L.tagNames[tag] || tag, tagCounts[tag], state.tags.has(tag));
  }
  const noiseCount = posts.filter(isNoise).length;
  if (noiseCount) {
    thtml += chipHtml("noise:toggle", "chip-plain", L.noiseChip, noiseCount, state.showNoise);
  }
  $("tag-chips").innerHTML = thtml;

  let shtml = `<span class="chip-label">${escapeHtml(L.sortLabel)}</span>`;
  shtml += chipHtml("sort:priority", "chip-orange", L.sortPriority, null, state.sort === "priority");
  shtml += chipHtml("sort:latest", "chip-plain", L.sortLatest, null, state.sort === "latest");
  $("sort-chips").innerHTML = shtml;
}

function renderAccounts() {
  const posts = state.data.posts || [];
  const counts = {};
  posts.forEach(p => { counts[p.handle] = (counts[p.handle] || 0) + 1; });
  const L = t();
  const catNames = { core: L.catCore, strong: L.catStrong, extra: L.catExtra, zhtw: L.catZh };
  let html = "";
  for (const [handle, meta] of Object.entries(ACCOUNT_META)) {
    const color = CATEGORIES[meta.category].color;
    html += `<button class="account" data-account="${handle}" style="--acc:${color}"` +
      ` aria-pressed="${state.account === handle}">` +
      `<span class="acc-head">` +
        `<span class="ava" aria-hidden="true">${escapeHtml(handle[0].toUpperCase())}</span>` +
        `<span class="handle">@${handle}</span>` +
        `<span class="cat">${escapeHtml(catNames[meta.category])}</span>` +
      `</span>` +
      `<div class="desc">${escapeHtml(meta.desc[state.lang])}</div>` +
      `<div class="count">${escapeHtml(L.postsCount(counts[handle] || 0))}</div>` +
      `</button>`;
  }
  $("account-list").innerHTML = html;
}

function renderFeed() {
  const L = t();
  const posts = visiblePosts();
  if (state.sort === "priority") {
    posts.sort((a, b) => (isPriority(b) - isPriority(a)) ||
      (Date.parse(b.created_at || 0) || 0) - (Date.parse(a.created_at || 0) || 0));
  }
  const title = MODE === "archive" ? L.feedTitleArchive : L.feedTitle;
  $("feed-title").textContent = `${title} — ${L.postsCount(posts.length)}`;
  if (!posts.length) {
    const noFilters = !state.q.trim() && !state.watchOnly && state.cat === "all" &&
      !state.tags.size && !state.account;
    const msg = MODE === "archive" && noFilters ? L.emptyArchive : L.empty;
    $("feed").innerHTML = `<div class="empty">${GHOST_SVG}<p>${escapeHtml(msg)}</p></div>`;
    return;
  }
  $("feed").innerHTML = posts.map(p => {
    const meta = ACCOUNT_META[p.handle];
    const accColor = meta ? CATEGORIES[meta.category].color : "var(--muted)";
    const mainTag = (p.tags || ["other"])[0];
    const tagColor = (TAGS[mainTag] || TAGS.other).color;
    let tags = (p.tags || []).map(tag =>
      `<span class="tag" style="--tc:${(TAGS[tag] || TAGS.other).color}">${escapeHtml(t().tagNames[tag] || tag)}</span>`
    ).join("");
    const kwHits = matchedKeywords(p);
    const watched = matchCountry(p) || kwHits.length > 0;
    if (kwHits.length) {
      tags = kwHits.slice(0, 2).map(k =>
        `<span class="tag tag-kw">★ ${escapeHtml(k)}</span>`).join("") + tags;
    }
    if (matchCountry(p)) {
      tags = `<span class="tag tag-watch">⚑ ${escapeHtml(L.watchTag(COUNTRIES[state.watch][state.lang]))}</span>` + tags;
    }
    const openLabel = (p.url || "").includes("x.com/") ? L.openOnX : L.openSource;
    /* zh mode shows the cached translation when available, with a
       per-card toggle back to the original text */
    const hasZh = state.lang === "zh" && p.text_zh;
    const showingOrig = state.showOrig.has(p.id);
    const bodyText = hasZh && !showingOrig ? p.text_zh : (p.text || "");
    let transUi = "";
    if (hasZh) {
      transUi = `<button class="mt-toggle" data-orig="${escapeHtml(p.id)}" aria-pressed="${showingOrig}">` +
        `${escapeHtml(showingOrig ? L.showTrans : L.showOrig)}</button>` +
        (showingOrig ? "" : `<span class="mt-note">${escapeHtml(L.mtNote)}</span>`);
    }
    const prio = isPriority(p) ? `<span class="prio">${escapeHtml(L.priorityBadge)}</span>` : "";
    return `<article class="card${watched ? " card-watch" : ""}" style="--tagc:${tagColor};--acc:${accColor}">` +
      `<div class="card-head">` +
        `<a class="handle" href="https://x.com/${p.handle}" target="_blank" rel="noopener noreferrer">@${p.handle}</a>` +
        `<span class="name">${escapeHtml(p.name || (meta ? meta.name : ""))}</span>` + prio +
        `<time datetime="${escapeHtml(p.created_at || "")}" title="${escapeHtml(fmtUtc(p.created_at))}">${escapeHtml(timeAgo(p.created_at))}</time>` +
      `</div>` +
      `<p class="card-text">${linkify(escapeHtml(bodyText))}</p>` +
      `<div class="card-foot">${tags}${transUi}` +
        `<a class="open-link" href="${escapeHtml(p.url || "#")}" target="_blank" rel="noopener noreferrer">${escapeHtml(openLabel)}</a>` +
      `</div></article>`;
  }).join("");
}

function renderMeta() {
  const L = t();
  const d = state.data;
  $("updated-at").textContent = fmtLocal(d.generated_at);
  $("updated-at").title = fmtUtc(d.generated_at);
  $("source").textContent = L.sources[d.source] || d.source || "—";
  $("post-count").textContent = (d.posts || []).length;
  const hasNew = typeof d.new_count === "number";
  $("new-count-pill").hidden = !hasNew;
  if (hasNew) $("new-count").textContent = d.new_count;
  $("sample-banner").hidden = d.source !== "sample";
}

function renderAll() {
  renderStatic();
  renderMeta();
  renderAlert();
  renderNav();
  renderChips();
  renderAccounts();
  renderFeed();
}

/* ================= events ================= */
document.addEventListener("click", ev => {
  const orig = ev.target.closest("[data-orig]");
  if (orig) {
    const id = orig.dataset.orig;
    state.showOrig.has(id) ? state.showOrig.delete(id) : state.showOrig.add(id);
    renderFeed();
    return;
  }
  const chip = ev.target.closest("[data-chip]");
  if (chip) {
    const [kind, value] = chip.dataset.chip.split(":");
    if (kind === "cat") state.cat = value;
    else if (kind === "tag") state.tags.has(value) ? state.tags.delete(value) : state.tags.add(value);
    else if (kind === "noise") state.showNoise = !state.showNoise;
    else if (kind === "sort") { state.sort = value; savePref("dw-sort", value); }
    renderChips(); renderFeed();
    return;
  }
  const acc = ev.target.closest("[data-account]");
  if (acc) {
    state.account = state.account === acc.dataset.account ? null : acc.dataset.account;
    renderAccounts(); renderFeed();
  }
});
$("search").addEventListener("input", ev => { state.q = ev.target.value; renderFeed(); });
$("lang-zh").addEventListener("click", () => setLang("zh"));
$("lang-en").addEventListener("click", () => setLang("en"));
function toggleWatchOnly() {
  const hasMatches = (state.data.posts || []).some(matchWatch);
  if (!hasMatches && !state.watchOnly) return;
  state.watchOnly = !state.watchOnly;
  renderAlert(); renderFeed();
  if (state.watchOnly) $("feed-title").scrollIntoView({ behavior: "smooth", block: "start" });
}
/* the whole alert bar toggles the filter (except country selector and keyword editor) */
$("alert-bar").addEventListener("click", ev => {
  if (ev.target.closest(".watch-wrap") || ev.target.closest(".kw-wrap")) return;
  toggleWatchOnly();
});
$("alert-bar").addEventListener("keydown", ev => {
  if ((ev.key === "Enter" || ev.key === " ") &&
      !ev.target.closest(".watch-wrap") && !ev.target.closest(".kw-wrap")) {
    ev.preventDefault();
    toggleWatchOnly();
  }
});
/* user watch keywords: Enter adds, chip click removes */
function saveKeywords() {
  savePref("dw-keywords", JSON.stringify(state.keywords));
  renderAlert(); renderFeed();
}
$("kw-input").addEventListener("keydown", ev => {
  if (ev.key !== "Enter") return;
  ev.preventDefault();
  const kw = ev.target.value.trim().slice(0, 40);
  if (kw && !state.keywords.some(k => k.toLowerCase() === kw.toLowerCase()) &&
      state.keywords.length < 20) {
    state.keywords.push(kw);
    saveKeywords();
  }
  const input = $("kw-input");
  input.value = "";
  input.focus();
});
document.addEventListener("click", ev => {
  const del = ev.target.closest("[data-kw-del]");
  if (del) {
    state.keywords = state.keywords.filter(k => k !== del.dataset.kwDel);
    saveKeywords();
  }
});
$("watch-country").addEventListener("change", ev => {
  state.watch = ev.target.value;
  savePref("dw-watch", state.watch);
  renderAlert(); renderFeed();
});
function setLang(lang) {
  state.lang = lang;
  savePref("dw-lang", lang);
  renderAll();
}

/* ================= live data + clock ================= */
async function loadLive() {
  try {
    const resp = await fetch("data/feed.json", { cache: "no-store" });
    if (!resp.ok) return;
    const data = await resp.json();
    if (data && Array.isArray(data.posts) && data.posts.length) {
      state.data = data;
      renderAll();
    }
  } catch (err) { /* offline / preview mode — keep seed data */ }
}
function tickClock() {
  $("clock").textContent = new Date().toISOString().slice(0, 19).replace("T", " ") + " UTC";
}

const heroArt = $("hero-art");
if (heroArt) heroArt.innerHTML = MASCOT_HERO;
renderAll();
tickClock();
setInterval(tickClock, 1000);
loadLive();
setInterval(loadLive, 10 * 60 * 1000);
