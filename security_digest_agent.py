"""
Security Digest Agent
- RSS 피드 수집 (Socket.dev blog, r/netsec)
- Claude API로 요약·심각도 분류
- Slack Webhook으로 배치 전송
- 3시간마다 GitHub Actions에서 실행
"""

import os
import json
import time
import hashlib
import feedparser
import anthropic
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── 설정 ──────────────────────────────────────────────────────────────────────
FEEDS = {
    "Socket.dev Blog": "https://socket.dev/blog/rss.xml",
    "r/netsec":        "https://www.reddit.com/r/netsec/.rss",
}

LOOKBACK_HOURS = 3          # 최근 N시간 이내 항목만 수집
MAX_ITEMS_PER_FEED = 10     # 피드당 최대 항목 수
SEEN_FILE = ".seen_items.json"  # 중복 방지용 캐시 (repo에 커밋하거나 Actions cache 활용)

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]

# ── 유틸 ──────────────────────────────────────────────────────────────────────

def item_id(entry: dict) -> str:
    """항목 고유 ID (URL 기반 해시)"""
    key = entry.get("link") or entry.get("id") or entry.get("title", "")
    return hashlib.md5(key.encode()).hexdigest()


def load_seen() -> set:
    if Path(SEEN_FILE).exists():
        return set(json.loads(Path(SEEN_FILE).read_text()))
    return set()


def save_seen(seen: set):
    Path(SEEN_FILE).write_text(json.dumps(list(seen)))


def parse_published(entry) -> datetime | None:
    """feedparser published_parsed → datetime(UTC)"""
    t = entry.get("published_parsed") or entry.get("updated_parsed")
    if not t:
        return None
    return datetime(*t[:6], tzinfo=timezone.utc)


# ── RSS 수집 ──────────────────────────────────────────────────────────────────

def fetch_new_items(seen: set) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    new_items = []

    for source, url in FEEDS.items():
        feed = feedparser.parse(url)
        count = 0

        for entry in feed.entries:
            if count >= MAX_ITEMS_PER_FEED:
                break

            uid = item_id(entry)
            if uid in seen:
                continue

            published = parse_published(entry)
            if published and published < cutoff:
                continue

            new_items.append({
                "uid":     uid,
                "source":  source,
                "title":   entry.get("title", "(제목 없음)"),
                "link":    entry.get("link", ""),
                "summary": entry.get("summary", "")[:800],  # 토큰 절약
                "published": published.isoformat() if published else "unknown",
            })
            seen.add(uid)
            count += 1

    return new_items


# ── Claude 요약·분류 ──────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}

def analyze_with_claude(items: list[dict]) -> list[dict]:
    """Claude API로 각 항목 심각도 분류 + 한 줄 요약"""
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    items_text = "\n\n".join(
        f"[{i+1}] SOURCE: {it['source']}\nTITLE: {it['title']}\nSUMMARY: {it['summary']}"
        for i, it in enumerate(items)
    )

    prompt = f"""아래는 보안 관련 뉴스/블로그 항목들입니다.
각 항목에 대해 JSON 배열로만 응답하세요. 다른 텍스트는 절대 포함하지 마세요.

항목:
{items_text}

응답 형식 (JSON 배열):
[
  {{
    "index": 1,
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "one_line": "한국어로 핵심만 한 문장 요약 (60자 이내)",
    "tags": ["npm", "supply-chain"] // 관련 태그 1~3개
  }},
  ...
]

심각도 기준:
- CRITICAL: 즉시 패치 필요한 RCE·인증 우회·악성 패키지 배포
- HIGH: 데이터 유출 가능·권한 상승·활발히 악용 중
- MEDIUM: 취약점 공개됐으나 악용 제한적
- LOW: 보안 권고·모범사례·마이너 버그
- INFO: 뉴스·트렌드·분석 글"""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = response.content[0].text.strip()
    # 혹시 마크다운 펜스 포함 시 제거
    raw = raw.replace("```json", "").replace("```", "").strip()
    analyses = json.loads(raw)

    # 원본 items에 분석 결과 병합
    analysis_map = {a["index"]: a for a in analyses}
    for i, item in enumerate(items):
        a = analysis_map.get(i + 1, {})
        item["severity"] = a.get("severity", "INFO")
        item["one_line"] = a.get("one_line", item["title"])
        item["tags"] = a.get("tags", [])

    return items


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

    # 심각도 순 정렬
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    items_sorted = sorted(items, key=lambda x: order.index(x.get("severity", "INFO")))

    for item in items_sorted:
        emoji = SEVERITY_EMOJI.get(item["severity"], "⚪")
        tags  = "  ".join(f"`{t}`" for t in item.get("tags", []))
        text  = (
            f"{emoji} *{item['severity']}*  {tags}\n"
            f"*<{item['link']}|{item['title']}>*\n"
            f"{item['one_line']}\n"
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
        status = resp.getcode()
        print(f"Slack 전송 완료: HTTP {status} | {len(items)}건")


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

    print("Claude API로 분석 중...")
    analyzed = analyze_with_claude(new_items)

    send_to_slack(analyzed)
    save_seen(seen)
    print("완료")


if __name__ == "__main__":
    main()