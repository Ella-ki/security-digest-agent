"""
Security Digest Agent (룰 기반 + 한글 번역)
- RSS 피드 수집 (Snyk Blog, r/netsec)
- 키워드 룰로 심각도 분류 + 태그 자동 추출
- 제목 한글 번역 (deep-translator)
- Slack Webhook으로 배치 전송
- 3시간마다 GitHub Actions에서 실행
"""

import os
import json
import hashlib
import feedparser
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from deep_translator import GoogleTranslator

# ── 설정 ──────────────────────────────────────────────────────────────────────
FEEDS = {
    "Snyk Blog": "https://snyk.io/blog/feed/",
    "r/netsec":  "https://www.reddit.com/r/netsec/.rss",
}

LOOKBACK_HOURS = 72
MAX_ITEMS_PER_FEED = 10
SEEN_FILE = ".seen_items.json"

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]

# ── 심각도 룰 ─────────────────────────────────────────────────────────────────
SEVERITY_RULES = [
    ("CRITICAL", [
        "remote code execution", "rce", "zero-day", "0-day", "0day",
        "supply chain attack", "malicious package", "malicious npm",
        "malicious pypi", "backdoor", "actively exploited",
        "authentication bypass", "unauthenticated rce",
    ]),
    ("HIGH", [
        "cve-", "data breach", "privilege escalation", "credential theft",
        "infostealer", "ransomware", "critical vulnerability",
        "arbitrary code", "sql injection", "xss", "ssrf",
        "typosquatting", "phishing campaign", "apt ",
    ]),
    ("MEDIUM", [
        "vulnerability", "exploit", "patch", "security advisory",
        "disclosure", "poc", "proof of concept", "misconfiguration",
        "exposed", "leaked", "bypass",
    ]),
    ("LOW", [
        "security", "hardening", "best practice", "compliance",
        "audit", "pentest", "ctf", "bounty",
    ]),
]

TAG_RULES = {
    "npm":          ["npm", "node.js", "nodejs", "package.json"],
    "pypi":         ["pypi", "pip ", "python package"],
    "supply-chain": ["supply chain", "typosquatting", "malicious package", "dependency"],
    "cve":          ["cve-"],
    "rce":          ["remote code execution", "rce"],
    "ransomware":   ["ransomware"],
    "phishing":     ["phishing"],
    "apt":          ["apt ", "nation-state", "threat actor"],
    "browser":      ["chrome", "firefox", "browser extension"],
    "cloud":        ["aws", "azure", "gcp", "cloud"],
    "linux":        ["linux", "ubuntu", "debian"],
    "windows":      ["windows", "microsoft"],
    "mobile":       ["android", "ios", "mobile"],
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}

# ── 유틸 ──────────────────────────────────────────────────────────────────────

def item_id(entry) -> str:
    key = entry.get("link") or entry.get("id") or entry.get("title", "")
    return hashlib.md5(key.encode()).hexdigest()


def load_seen() -> set:
    if Path(SEEN_FILE).exists():
        return set(json.loads(Path(SEEN_FILE).read_text()))
    return set()


def save_seen(seen: set):
    Path(SEEN_FILE).write_text(json.dumps(list(seen)))


def parse_published(entry) -> datetime | None:
    t = entry.get("published_parsed") or entry.get("updated_parsed")
    if not t:
        return None
    return datetime(*t[:6], tzinfo=timezone.utc)


# ── 분류 ──────────────────────────────────────────────────────────────────────

def classify(title: str, summary: str) -> tuple[str, list[str]]:
    text = (title + " " + summary).lower()

    severity = "INFO"
    for level, keywords in SEVERITY_RULES:
        if any(kw in text for kw in keywords):
            severity = level
            break

    tags = [tag for tag, keywords in TAG_RULES.items() if any(kw in text for kw in keywords)][:3]

    return severity, tags


# ── 번역 ──────────────────────────────────────────────────────────────────────

def translate_titles(items: list[dict]) -> list[dict]:
    """제목 일괄 번역 (실패 시 원문 유지)"""
    translator = GoogleTranslator(source='en', target='ko')
    for item in items:
        try:
            item["title_ko"] = translator.translate(item["title"])
        except Exception as e:
            print(f"[번역 실패] {item['title'][:40]}... → {e}")
            item["title_ko"] = item["title"]  # 실패 시 원문 유지
    return items


# ── RSS 수집 ──────────────────────────────────────────────────────────────────

def fetch_new_items(seen: set) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    new_items = []

    for source, url in FEEDS.items():
        feed = feedparser.parse(url)
        print(f"[{source}] {len(feed.entries)}개 수신")
        count = 0

        for entry in feed.entries:
            if count >= MAX_ITEMS_PER_FEED:
                break

            uid = item_id(entry)
            if uid in seen:
                continue

            published = parse_published(entry)
            if published is not None and published < cutoff:
                continue

            title   = entry.get("title", "(제목 없음)")
            summary = entry.get("summary", "")[:500]
            severity, tags = classify(title, summary)

            new_items.append({
                "uid":       uid,
                "source":    source,
                "title":     title,
                "title_ko":  "",  # 번역 후 채워짐
                "link":      entry.get("link", ""),
                "severity":  severity,
                "tags":      tags,
                "published": published.isoformat() if published else "unknown",
            })
            seen.add(uid)
            count += 1

    return new_items


# ── Slack 전송 ────────────────────────────────────────────────────────────────

def build_slack_blocks(items: list[dict]) -> list[dict]:
    now_kst = datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M KST")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🛡️ Security Digest  |  {now_kst}"}
        },
        {"type": "divider"}
    ]

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    items_sorted = sorted(items, key=lambda x: order.index(x.get("severity", "INFO")))

    for item in items_sorted:
        emoji    = SEVERITY_EMOJI.get(item["severity"], "⚪")
        tags     = "  ".join(f"`{t}`" for t in item.get("tags", []))
        title_ko = item.get("title_ko") or item["title"]
        text = (
            f"{emoji} *{item['severity']}*  {tags}\n"
            f"*<{item['link']}|{item['title']}>*\n"
            f"{title_ko}\n"
            f"_출처: {item['source']}_"
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": text}
        })
        blocks.append({"type": "divider"})

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"총 {len(items)}건 | 최근 {LOOKBACK_HOURS}시간 이내 항목"}]
    })

    return blocks


def send_to_slack(items: list[dict]):
    if not items:
        print("새 항목 없음 — Slack 전송 스킵")
        return

    blocks = build_slack_blocks(items)
    payload = json.dumps({"blocks": blocks}).encode("utf-8")

    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        print(f"Slack 전송 완료: HTTP {resp.getcode()} | {len(items)}건")


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main():
    print(f"[{datetime.now().isoformat()}] Security Digest Agent 시작")

    seen = load_seen()
    print(f"기존 캐시: {len(seen)}개 항목")

    new_items = fetch_new_items(seen)
    print(f"새 항목 수집: {len(new_items)}건")

    if not new_items:
        print("새 항목 없음 — 종료")
        save_seen(seen)
        return

    print("번역 중...")
    new_items = translate_titles(new_items)

    send_to_slack(new_items)
    save_seen(seen)
    print("완료")


if __name__ == "__main__":
    main()