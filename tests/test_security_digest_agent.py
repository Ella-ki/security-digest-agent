import os
import sys
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SLACK_WEBHOOK_URL", "https://hooks.slack.invalid/test")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import security_digest_agent as agent  # noqa: E402
from deep_translator.exceptions import TooManyRequests  # noqa: E402


def make_item(uid: str, severity: str = "INFO", title: str = "Some title") -> dict:
    return {
        "uid": uid, "source": "Test", "title": title, "title_ko": "",
        "link": "https://example.com", "severity": severity, "tags": [], "published": "unknown",
    }


class ChunkedTest(unittest.TestCase):
    def test_splits_into_fixed_size_chunks(self):
        self.assertEqual(agent.chunked([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]])

    def test_empty_list_returns_no_chunks(self):
        self.assertEqual(agent.chunked([], 3), [])

    def test_rejects_non_positive_size(self):
        with self.assertRaises(ValueError):
            agent.chunked([1], 0)


class SendToSlackTest(unittest.TestCase):
    def test_marks_seen_only_after_successful_send(self):
        items = [make_item(f"uid{index}") for index in range(3)]
        seen = set()
        with mock.patch.object(agent, "post_to_slack", return_value=200):
            agent.send_to_slack(items, seen)
        self.assertEqual(seen, {"uid0", "uid1", "uid2"})

    def test_failed_send_leaves_items_unseen(self):
        items = [make_item("uid0")]
        seen = set()
        with mock.patch.object(agent, "post_to_slack", side_effect=OSError("network down")):
            with self.assertRaises(OSError):
                agent.send_to_slack(items, seen)
        self.assertEqual(seen, set())

    def test_partial_failure_keeps_only_sent_chunks(self):
        items = [make_item(f"uid{index}") for index in range(agent.MAX_ITEMS_PER_MESSAGE + 1)]
        seen = set()
        with mock.patch.object(agent, "post_to_slack", side_effect=[200, OSError("fail")]):
            with self.assertRaises(OSError):
                agent.send_to_slack(items, seen)
        self.assertEqual(len(seen), agent.MAX_ITEMS_PER_MESSAGE)

    def test_each_message_stays_within_slack_block_limit(self):
        items = [make_item(f"uid{index}") for index in range(45)]
        sent_blocks = []
        with mock.patch.object(agent, "post_to_slack", side_effect=lambda blocks: sent_blocks.append(blocks) or 200):
            agent.send_to_slack(items, set())
        self.assertEqual(len(sent_blocks), 3)
        self.assertTrue(all(len(blocks) <= 50 for blocks in sent_blocks))


class BuildSlackBlocksTest(unittest.TestCase):
    def test_omits_duplicate_line_when_translation_equals_title(self):
        item = make_item("uid0", title="Same")
        item["title_ko"] = "Same"
        text = agent.build_slack_blocks([item])[2]["text"]["text"]
        self.assertEqual(text.count("Same"), 1)

    def test_includes_korean_title_when_translated(self):
        item = make_item("uid0", title="Hello")
        item["title_ko"] = "안녕"
        text = agent.build_slack_blocks([item])[2]["text"]["text"]
        self.assertIn("안녕", text)


class TranslateTitlesTest(unittest.TestCase):
    def test_fills_title_ko_from_translation(self):
        items = [make_item("uid0", title="Hello")]
        with mock.patch.object(agent, "translate_with_google", return_value=["안녕"]):
            agent.translate_titles(items)
        self.assertEqual(items[0]["title_ko"], "안녕")

    def test_google_stops_after_rate_limit_and_keeps_originals(self):
        translator = mock.Mock()
        translator.translate.side_effect = ["하나", TooManyRequests()]
        with mock.patch.object(agent, "GoogleTranslator", return_value=translator):
            result = agent.translate_with_google(["one", "two", "three"])
        self.assertEqual(result, ["하나", "two", "three"])
        self.assertEqual(translator.translate.call_count, 2)


if __name__ == "__main__":
    unittest.main()
