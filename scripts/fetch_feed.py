#!/usr/bin/env python3
"""Fetch latest posts from curated dark-web threat-intel accounts on X (Twitter).

Data sources, in order of preference:
  1. X API v2  -- used when the X_BEARER_TOKEN environment variable is set.
  2. Nitter RSS mirrors -- keyless fallback; instances are tried in order.

Output: data/feed.json, merged with previously fetched posts so a partial
fetch never loses history. Designed to run from GitHub Actions on a schedule
(twice daily, around 05:00 and 13:00 Taipei time / 21:00 and 05:00 UTC).
Only uses the Python standard library.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "feed.json"

# category: core = 高度推薦(暗網專門), strong = 強力推薦(威脅情報),
#           news = 資安新聞, extra = 補充推薦, zhtw = 中文情資
ACCOUNTS = [
    {"handle": "DailyDarkWeb", "category": "core"},
    {"handle": "DarkWebInformer", "category": "core"},
    {"handle": "jms_dot_py", "category": "strong"},
    {"handle": "campuscodi", "category": "strong"},
    {"handle": "GossiTheDog", "category": "strong"},
    {"handle": "GroupIB_TI", "category": "strong"},
    {"handle": "CTI_Alerts", "category": "strong"},
    {"handle": "TheDFIRReport", "category": "strong"},
    {"handle": "SwiftOnSecurity", "category": "news"},
    {"handle": "darkreading", "category": "news"},
    {"handle": "TheHackersNews", "category": "news"},
    {"handle": "MsftSecIntel", "category": "news"},
    {"handle": "threatintel", "category": "news"},
    {"handle": "CyberSec__News", "category": "news"},
    {"handle": "The_Cyber_News", "category": "news"},
    {"handle": "briankrebs", "category": "extra"},
    {"handle": "vxunderground", "category": "extra"},
    {"handle": "Gi7w0rm", "category": "extra"},
    {"handle": "MonThreat", "category": "extra"},
    {"handle": "troyhunt", "category": "extra"},
    {"handle": "InfoSec_zip", "category": "zhtw"},
    {"handle": "twcertcc", "category": "zhtw"},
    {"handle": "TeamT5_Official", "category": "zhtw"},
]

NITTER_INSTANCES = [
    "https://nitter.net",
    "https://nitter.poast.org",
    "https://nitter.privacyredirect.com",
    "https://nitter.space",
    "https://lightbrd.com",
]

# Mastodon mirrors, used only when every Nitter instance fails for an
# account. These authors cross-post the same threat intel there.
MASTODON_FEEDS = {
    "GossiTheDog": "https://cyberplace.social/@GossiTheDog.rss",
    "campuscodi": "https://mastodon.social/@campuscodi.rss",
}

TAG_RULES = [
    ("ransomware", re.compile(r"ransom", re.I)),
    ("breach", re.compile(r"breach|leak|stolen|exfiltrat|\bdump\b|database.{0,20}(sale|sold|expos)", re.I)),
    ("market", re.compile(r"darknet market|dark ?web market|underground (market|forum)|for sale|selling access|marketplace", re.I)),
    ("malware", re.compile(r"malware|stealer|botnet|trojan|\brat\b|loader|backdoor|infostealer|spyware", re.I)),
    ("vuln", re.compile(r"\bcve-\d|vulnerab|exploit|0.?day|zero.?day|\bpoc\b|patch(es|ed)?\b", re.I)),
    ("darkweb", re.compile(r"\.onion\b|onion (service|site|link|domain)s?|tor (hidden|network|browser)|hidden service|dark ?web|darknet", re.I)),
]

# Security-signal scoring: 0 = no security relevance (hidden by default
# on the site), >=3 = high-priority intel (badged and sorted first).
SIGNAL_RULES = [
    (3, re.compile(r"\bcve-\d{4}-\d+|\biocs?\b|ransom|data (leak|breach)|victim|\.onion\b|zero.?day|\b0.?day\b", re.I)),
    (2, re.compile(r"exploit|malware|stealer|botnet|breach|leak(ed|s|age)?\b|dark ?web|darknet|threat actor|credential|infostealer", re.I)),
    (1, re.compile(r"vulnerab|phishing|hack(ed|er|ing)|securit|infosec|\bapt\b|threat intel|patch(es|ed)?\b|backdoor|\btor\b|osint|\bddos\b|c2\b", re.I)),
]


def score_post(text):
    return sum(w for w, rx in SIGNAL_RULES if rx.search(text))

# Keep history for the archive page without letting feed.json grow
# unbounded now that 22 accounts are tracked.
MAX_PER_ACCOUNT = 40
MAX_TOTAL_POSTS = 800

# Keyless Google Translate endpoint used to cache a zh-TW rendition of
# each post (text_zh). Translations are incremental: only posts that
# don't have one yet are translated, capped per run. POSTed because
# long posts overflow a GET query string.
TRANSLATE_URL = "https://translate.googleapis.com/translate_a/single"
MAX_TRANSLATIONS_PER_RUN = 80
MAX_CONSECUTIVE_TRANSLATE_FAILURES = 3
USER_AGENT = "DarkWebInfoFetch/1.0 (threat intel aggregator; github.com/chinchiang/DarkWebInfoFetch)"


def log(msg):
    print(msg, file=sys.stderr)


def http_get(url, headers=None, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def classify(text):
    tags = [tag for tag, rx in TAG_RULES if rx.search(text)]
    return tags or ["other"]


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- X API v2

def fetch_via_x_api(token):
    """Returns (posts, status_by_handle)."""
    headers = {"Authorization": f"Bearer {token}"}
    posts, status = [], {}

    usernames = ",".join(a["handle"] for a in ACCOUNTS)
    url = ("https://api.x.com/2/users/by?usernames="
           f"{urllib.parse.quote(usernames)}&user.fields=name")
    try:
        _, body = http_get(url, headers)
        users = {u["username"].lower(): u for u in json.loads(body).get("data", [])}
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, OSError) as exc:
        log(f"[x-api] user lookup failed: {exc}")
        return [], {a["handle"]: "error" for a in ACCOUNTS}

    for account in ACCOUNTS:
        handle = account["handle"]
        user = users.get(handle.lower())
        if not user:
            status[handle] = "not_found"
            continue
        tweets_url = (
            f"https://api.x.com/2/users/{user['id']}/tweets"
            "?max_results=25&exclude=retweets,replies"
            "&tweet.fields=created_at,public_metrics"
        )
        try:
            _, body = http_get(tweets_url, headers)
            data = json.loads(body).get("data", [])
        except urllib.error.HTTPError as exc:
            status[handle] = "rate_limited" if exc.code == 429 else f"http_{exc.code}"
            if exc.code == 429:
                log("[x-api] rate limited, stopping early")
                break
            continue
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError) as exc:
            log(f"[x-api] {handle}: {exc}")
            status[handle] = "error"
            continue

        for tweet in data:
            text = tweet.get("text", "").strip()
            posts.append({
                "id": tweet["id"],
                "handle": handle,
                "name": user.get("name", handle),
                "text": text,
                "url": f"https://x.com/{handle}/status/{tweet['id']}",
                "created_at": tweet.get("created_at", ""),
                "tags": classify(text),
            })
        status[handle] = "ok"
        time.sleep(1.5)  # stay friendly with per-endpoint rate limits

    return posts, status


# ------------------------------------------------------------- Nitter RSS

def parse_rss(xml_bytes, handle):
    posts = []
    root = ET.fromstring(xml_bytes)
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip()
        title = unescape((item.findtext("title") or "").strip())
        pub = (item.findtext("pubDate") or "").strip()
        match = re.search(r"/status/(\d+)", link)
        if not match or not title:
            continue
        # Skip retweets surfaced by Nitter ("RT by @user: ...")
        if title.startswith("RT by"):
            continue
        try:
            created = iso(parsedate_to_datetime(pub))
        except (TypeError, ValueError):
            created = ""
        tweet_id = match.group(1)
        posts.append({
            "id": tweet_id,
            "handle": handle,
            "name": handle,
            "text": title,
            "url": f"https://x.com/{handle}/status/{tweet_id}",
            "created_at": created,
            "tags": classify(title),
        })
    return posts


HTML_TAG = re.compile(r"<[^>]+>")


def parse_mastodon_rss(xml_bytes, handle):
    posts = []
    root = ET.fromstring(xml_bytes)
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip()
        desc = unescape(item.findtext("description") or "")
        text = re.sub(r"\s+", " ", HTML_TAG.sub(" ", desc)).strip()
        pub = (item.findtext("pubDate") or "").strip()
        if not link or not text:
            continue
        try:
            created = iso(parsedate_to_datetime(pub))
        except (TypeError, ValueError):
            created = ""
        match = re.search(r"/(\d+)/?$", link)
        posts.append({
            "id": f"md-{match.group(1)}" if match else link,
            "handle": handle,
            "name": handle,
            "text": text,
            "url": link,
            "created_at": created,
            "tags": classify(text),
        })
    return posts


def fetch_via_nitter():
    posts, status = [], {}
    for account in ACCOUNTS:
        handle = account["handle"]
        status[handle] = "error"
        for instance in NITTER_INSTANCES:
            try:
                code, body = http_get(f"{instance}/{handle}/rss")
                if code != 200 or not body.lstrip().startswith(b"<"):
                    continue
                account_posts = parse_rss(body, handle)
                if account_posts:
                    posts.extend(account_posts)
                    status[handle] = "ok"
                    break
            except (urllib.error.URLError, urllib.error.HTTPError, ET.ParseError,
                    TimeoutError, OSError):
                continue
        if status[handle] != "ok" and handle in MASTODON_FEEDS:
            try:
                code, body = http_get(MASTODON_FEEDS[handle])
                if code == 200 and body.lstrip().startswith(b"<"):
                    account_posts = parse_mastodon_rss(body, handle)
                    if account_posts:
                        posts.extend(account_posts)
                        status[handle] = "ok_mastodon"
            except (urllib.error.URLError, urllib.error.HTTPError, ET.ParseError,
                    TimeoutError, OSError):
                pass
        time.sleep(1)
    return posts, status


# ------------------------------------------------------------------ merge

def load_existing():
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def translate_zh(text):
    try:
        payload = urllib.parse.urlencode({
            "client": "gtx", "sl": "auto", "tl": "zh-TW", "dt": "t", "q": text,
        }).encode()
        req = urllib.request.Request(TRANSLATE_URL, data=payload, headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        })
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status != 200:
                return None
            segments = json.loads(resp.read())[0] or []
        return "".join(seg[0] for seg in segments if seg and seg[0]) or None
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            IndexError, TypeError, TimeoutError, OSError):
        return None


def add_translations(posts):
    done, consecutive_failures = 0, 0
    for post in posts:
        if post.get("text_zh") or post.get("sample") or not post.get("text"):
            continue
        if done >= MAX_TRANSLATIONS_PER_RUN:
            log(f"[translate] per-run cap reached ({MAX_TRANSLATIONS_PER_RUN})")
            break
        zh = translate_zh(post["text"])
        if zh is None:
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_TRANSLATE_FAILURES:
                log("[translate] too many consecutive failures, stopping for this run")
                break
            continue  # skip this post, try the next one
        consecutive_failures = 0
        post["text_zh"] = zh
        done += 1
        time.sleep(0.3)
    if done:
        log(f"[translate] translated {done} posts to zh-TW")


def merge(existing_posts, new_posts):
    by_id = {p["id"]: p for p in existing_posts}
    for post in new_posts:
        old = by_id.get(post["id"])
        # a re-fetched post replaces the stored one; keep its cached translation
        if old and old.get("text_zh") and not post.get("text_zh"):
            post["text_zh"] = old["text_zh"]
        by_id[post["id"]] = post
    merged = list(by_id.values())
    # Once real posts exist, drop the bundled sample placeholders.
    if any(not p.get("sample") for p in merged):
        merged = [p for p in merged if not p.get("sample")]
    merged.sort(key=lambda p: p.get("created_at", ""), reverse=True)
    capped, per_account = [], {}
    for post in merged:
        count = per_account.get(post["handle"], 0)
        if count < MAX_PER_ACCOUNT:
            capped.append(post)
            per_account[post["handle"]] = count + 1
    return capped[:MAX_TOTAL_POSTS]


def main():
    token = os.environ.get("X_BEARER_TOKEN", "").strip()
    if token:
        log("[fetch] using X API v2")
        new_posts, status = fetch_via_x_api(token)
        source = "x_api"
        if not new_posts:
            log("[fetch] X API returned nothing, falling back to Nitter RSS")
            new_posts, status = fetch_via_nitter()
            source = "nitter"
    else:
        log("[fetch] X_BEARER_TOKEN not set, using Nitter RSS")
        new_posts, status = fetch_via_nitter()
        source = "nitter"

    existing = load_existing()
    existing_ids = {p["id"] for p in existing.get("posts", []) if not p.get("sample")}
    fresh_count = len({p["id"] for p in new_posts} - existing_ids)
    posts = merge(existing.get("posts", []), new_posts)
    for post in posts:  # tags/score are derived from text: recompute so
        if post.get("sample"):  # stored posts pick up rule improvements
            continue
        post["tags"] = classify(post.get("text", ""))
        post["score"] = score_post(post.get("text", ""))
    add_translations(posts)

    if not new_posts:
        log("[fetch] no new posts fetched this run; keeping existing data")
        source = existing.get("source", source)

    feed = {
        "generated_at": iso(datetime.now(timezone.utc)),
        "source": source if new_posts else f"{source}_stale",
        "new_count": fresh_count,
        "account_status": status,
        "categories": {a["handle"]: a["category"] for a in ACCOUNTS},
        "posts": posts,
    }
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(feed, ensure_ascii=False, indent=1), encoding="utf-8")
    ok = sum(1 for s in status.values() if s.startswith("ok"))
    log(f"[fetch] done: {len(new_posts)} fetched, {fresh_count} new, {len(posts)} total, "
        f"{ok}/{len(ACCOUNTS)} accounts ok")


if __name__ == "__main__":
    main()
