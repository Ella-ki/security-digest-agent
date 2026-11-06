"""
Security Digest Agent (룰 기반 + 한글 번역)
- RSS 피드 수집 (Snyk Blog, The Hacker News)
- GitHub Advisory Database 수집 (REST API, 인증 필요)
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
from deep_translator.exceptions import TooManyRequests

# ── 설정 ──────────────────────────────────────────────────────────────────────
FEEDS = {
    "Snyk Blog":       "https://snyk.io/blog/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
}

LOOKBACK_HOURS = 6
MAX_ITEMS_PER_FEED = 10
SEEN_FILE = ".seen_items.json"

# GitHub Advisory Database (REST API — RSS/Atom은 deprecated)
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories?per_page=20&sort=published&direction=desc"
GITHUB_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "moderate": "MEDIUM",
    "low":      "LOW",
}

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]

# Slack 메시지당 블록 최대 50개 제한 — 항목당 2블록 + 헤더/구분선/푸터 3블록
MAX_ITEMS_PER_MESSAGE = 20

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


def chunked(items: list, size: int) -> list[list]:
    """items를 size개씩 나눈 리스트 반환"""
    if size <= 0:
        raise ValueError("size는 1 이상이어야 합니다")
    return [items[start:start + size] for start in range(0, len(items), size)]


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

def translate_with_google(titles: list[str]) -> list[str]:
    """deep-translator의 Google 번역 (비공식 웹 엔드포인트 — 429 차단이 잦음).
    429를 받으면 나머지는 더 요청하지 않고 원문으로 둔다."""
    translator = GoogleTranslator(source="en", target="ko")
    translated = []
    for index, title in enumerate(titles):
        try:
            translated.append(translator.translate(title) or title)
        except TooManyRequests:
            print(f"[번역 실패] Google 429 차단 — 나머지 {len(titles) - index}건 원문 유지")
            translated.extend(titles[index:])
            break
        except Exception as e:
            print(f"[번역 실패] {title[:40]}... → {e}")
            translated.append(title)
    return translated


def translate_titles(items: list[dict]) -> list[dict]:
    """제목 일괄 번역 (실패 시 원문 유지)"""
    translated = translate_with_google([item["title"] for item in items])
    for item, title_ko in zip(items, translated):
        item["title_ko"] = title_ko
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
            count += 1

    return new_items


# ── GitHub Advisory Database 수집 (REST API) ──────────────────────────────────

def fetch_github_advisories(seen: set, cutoff: datetime) -> list[dict]:
    """GitHub Advisory Database를 REST API로 수집해 RSS item과 동일한 스키마로 변환.

    인증 필수: 비인증 호출은 rate limit이 매우 낮아 실사용 불가.
    GITHUB_TOKEN 환경변수가 없으면 건너뛰고 경고만 출력 (스크립트는 죽지 않음).
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[GitHub Advisory] GITHUB_TOKEN 미설정 — 수집 건너뜀")
        return []

    req = urllib.request.Request(
        GITHUB_ADVISORIES_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept":        "application/vnd.github+json",
            "User-Agent":    "security-digest-agent",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            advisories = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[GitHub Advisory] 수집 실패: {e}")
        return []

    print(f"[GitHub Advisory] {len(advisories)}개 수신")
    new_items = []
    count = 0

    for adv in advisories:
        if count >= MAX_ITEMS_PER_FEED:
            break

        ghsa_id = adv.get("ghsa_id") or adv.get("html_url", "")
        if not ghsa_id:
            continue
        uid = hashlib.md5(ghsa_id.encode()).hexdigest()
        if uid in seen:
            continue

        published = None
        published_at = adv.get("published_at")
        if published_at:
            try:
                published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
            except ValueError:
                published = None
        if published is not None and published < cutoff:
            continue

        title = adv.get("summary") or adv.get("cve_id") or ghsa_id

        severity = GITHUB_SEVERITY_MAP.get((adv.get("severity") or "").lower(), "INFO")

        # 태그: 영향받는 패키지의 ecosystem들 + cve_id 여부
        tags = []
        for vuln in adv.get("vulnerabilities") or []:
            pkg = (vuln.get("package") or {})
            eco = pkg.get("ecosystem")
            if eco and eco.lower() not in tags:
                tags.append(eco.lower())
        if adv.get("cve_id") and "cve" not in tags:
            tags.append("cve")
        tags = tags[:3]

        new_items.append({
            "uid":       uid,
            "source":    "GitHub Advisory",
            "title":     title,
            "title_ko":  "",  # 번역 후 채워짐
            "link":      adv.get("html_url", ""),
            "severity":  severity,
            "tags":      tags,
            "published": published.isoformat() if published else "unknown",
        })
        count += 1

    return new_items


# ── Slack 전송 ────────────────────────────────────────────────────────────────

def build_slack_blocks(items: list[dict], page: int = 1, total_pages: int = 1) -> list[dict]:
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
        title_ko = item.get("title_ko") or ""
        text = f"{emoji} *{item['severity']}*  {tags}\n*<{item['link']}|{item['title']}>*\n"
        if title_ko and title_ko != item["title"]:  # 번역 실패 시 같은 제목 두 번 출력 방지
            text += f"{title_ko}\n"
        text += f"_출처: {item['source']}_"
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": text}
        })
        blocks.append({"type": "divider"})

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"{page}/{total_pages} | {len(items)}건 | 최근 {LOOKBACK_HOURS}시간 이내 항목"}]
    })

    return blocks


def post_to_slack(blocks: list[dict]) -> int:
    payload = json.dumps({"blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.getcode()


def send_to_slack(items: list[dict], seen: set):
    """메시지 단위로 전송하고, 전송에 성공한 항목만 seen에 기록한다.
    실패 시 예외를 그대로 올려 워크플로가 실패로 표시되며, 미전송 항목은 다음 실행에서 재시도된다."""
    if not items:
        print("새 항목 없음 — Slack 전송 스킵")
        return

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    items_sorted = sorted(items, key=lambda x: order.index(x.get("severity", "INFO")))
    chunks = chunked(items_sorted, MAX_ITEMS_PER_MESSAGE)

    for page, chunk in enumerate(chunks, start=1):
        status = post_to_slack(build_slack_blocks(chunk, page, len(chunks)))
        seen.update(item["uid"] for item in chunk)
        print(f"Slack 전송 완료: HTTP {status} | {page}/{len(chunks)} | {len(chunk)}건")


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main():
    print(f"[{datetime.now().isoformat()}] Security Digest Agent 시작")

    seen = load_seen()
    print(f"기존 캐시: {len(seen)}개 항목")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)

    new_items = fetch_new_items(seen)
    new_items += fetch_github_advisories(seen, cutoff)
    print(f"새 항목 수집: {len(new_items)}건")

    if not new_items:
        print("새 항목 없음 — 종료")
        return

    print("번역 중...")
    new_items = translate_titles(new_items)

    try:
        send_to_slack(new_items, seen)
    finally:
        # seen에는 전송 성공분만 들어있으므로 실패해도 저장 — 실패분은 다음 실행에서 재시도
        save_seen(seen)
    print("완료")


if __name__ == "__main__":
    main()