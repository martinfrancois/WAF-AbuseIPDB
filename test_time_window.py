import json
import os
import runpy
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from time_window import build_time_window


class BuildTimeWindowTest(unittest.TestCase):
    def test_uses_the_configured_lookback_hours(self):
        now = datetime(2026, 7, 28, 16, 0, tzinfo=timezone.utc)

        range_from, range_until = build_time_window(now, 5)

        self.assertEqual(range_from, "2026-07-28T11:00:00Z")
        self.assertEqual(range_until, "2026-07-28T16:00:00Z")

    def test_rejects_non_positive_lookback(self):
        now = datetime(2026, 7, 28, 16, 0, tzinfo=timezone.utc)

        with self.assertRaisesRegex(ValueError, "positive"):
            build_time_window(now, 0)


class ReportWindowTest(unittest.TestCase):
    @patch.dict(
        os.environ,
        {
            "LOOKBACK_HOURS": "5",
            "CLOUDFLARE_ZONE_ID": "zone",
            "CLOUDFLARE_EMAIL": "email@example.com",
            "CLOUDFLARE_API_KEY": "cloudflare-key",
            "ABUSEIPDB_API_KEY": "abuse-key",
        },
    )
    @patch("requests.post")
    def test_report_uses_the_configured_lookback(self, post):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "data": {
                "viewer": {
                    "zones": [{"firewallEventsAdaptive": []}],
                }
            }
        }
        post.return_value = response

        runpy.run_path("main.py", run_name="__main__")

        payload = json.loads(post.call_args.kwargs["data"])
        report_filter = payload["variables"]["filter"]
        range_from = datetime.fromisoformat(report_filter["datetime_geq"].replace("Z", "+00:00"))
        range_until = datetime.fromisoformat(report_filter["datetime_leq"].replace("Z", "+00:00"))
        self.assertEqual((range_until - range_from).total_seconds(), 5 * 60 * 60)


if __name__ == "__main__":
    unittest.main()
