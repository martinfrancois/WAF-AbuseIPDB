import contextlib
import importlib
import io
import json
import unittest
from datetime import UTC, datetime
from unittest import mock

import httpx

import main

CONFIG_ENV = {
    "CLOUDFLARE_ZONE_ID": "zone",
    "CLOUDFLARE_EMAIL": "user@example.com",
    "CLOUDFLARE_API_KEY": "cloudflare-key",
    "ABUSEIPDB_API_KEY": "abuse-key",
    "PEPPER": "pepper",
    "IGNORED_IP_ADDRESSES": " 192.0.2.10, ,198.51.100.7 ",
}

NOW = datetime(2026, 7, 30, 12, 15, 0, tzinfo=UTC)


def config(**overrides):
    values = dict(CONFIG_ENV)
    values.update(overrides)
    return main.Config.from_env(values)


def event(**overrides):
    data = {
        "source": "firewallmanaged",
        "clientAsn": 64500,
        "clientASNDescription": "Example Network",
        "clientIP": "203.0.113.9",
        "clientRequestHTTPMethodName": "GET",
        "clientRequestHTTPProtocol": "HTTP/2",
        "clientRequestPath": "/",
        "clientRequestQuery": "",
        "datetime": "2026-07-30T10:00:00Z",
        "ruleId": "rule",
        "userAgent": "Mozilla/5.0",
    }
    data.update(overrides)
    return data


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_error=None, http_error=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {}
        self.json_error = json_error
        self.http_error = http_error

    def raise_for_status(self):
        if self.http_error:
            raise self.http_error

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


def cloudflare_payload(events=None):
    return {
        "data": {
            "viewer": {
                "zones": [
                    {
                        "firewallEventsAdaptive": list(events or []),
                    }
                ]
            }
        }
    }


class ConfigTest(unittest.TestCase):
    def test_import_without_environment_does_not_exit(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertIs(importlib.reload(main), main)

    def test_config_from_env_loads_required_and_optional_values(self):
        loaded = config()

        self.assertEqual(loaded.cloudflare_zone_id, "zone")
        self.assertEqual(loaded.cloudflare_email, "user@example.com")
        self.assertEqual(loaded.cloudflare_api_key, "cloudflare-key")
        self.assertEqual(loaded.abuseipdb_api_key, "abuse-key")
        self.assertEqual(loaded.pepper, "pepper")
        self.assertEqual(loaded.ignored_ip_addresses, ("192.0.2.10", "198.51.100.7"))

    def test_config_from_env_defaults_optional_values(self):
        env = dict(CONFIG_ENV)
        env.pop("PEPPER")
        env.pop("IGNORED_IP_ADDRESSES")

        loaded = main.Config.from_env(env)

        self.assertEqual(loaded.pepper, "")
        self.assertEqual(loaded.ignored_ip_addresses, ())

    def test_config_from_env_reports_missing_required_values(self):
        env = dict(CONFIG_ENV)
        env["CLOUDFLARE_EMAIL"] = ""
        env.pop("ABUSEIPDB_API_KEY")

        with self.assertRaisesRegex(
            main.ConfigError,
            "CLOUDFLARE_EMAIL, ABUSEIPDB_API_KEY",
        ):
            main.Config.from_env(env)

    def test_main_returns_failure_for_bad_config(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = main.main({})

        self.assertEqual(exit_code, 1)
        self.assertIn("Missing essential environment variables", stderr.getvalue())


class CloudflareTest(unittest.TestCase):
    def test_utc_time_window_handles_naive_now(self):
        naive_now = datetime(2026, 7, 30, 12, 15, 0)

        range_from, range_until = main.utc_time_window(naive_now)

        self.assertEqual(range_until.tzinfo, UTC)
        self.assertEqual(
            main.cloudflare_datetime(range_from),
            "2026-07-30T09:45:00Z",
        )

    def test_build_cloudflare_payload_uses_window_and_excluded_actions(self):
        range_from, range_until = main.utc_time_window(NOW)

        payload = main.build_cloudflare_payload(config(), range_from, range_until)

        self.assertEqual(payload["variables"]["zoneTag"], "zone")
        self.assertEqual(
            payload["variables"]["filter"]["datetime_geq"],
            "2026-07-30T09:45:00Z",
        )
        self.assertEqual(
            payload["variables"]["filter"]["AND"],
            [{"action_neq": action} for action in main.EXCLUDED_ACTIONS],
        )

    def test_get_blocked_ip_posts_payload_and_returns_json(self):
        calls = []

        def post(*args, **kwargs):
            calls.append((args, kwargs))
            return FakeResponse(payload=cloudflare_payload([event()]))

        response = main.get_blocked_ip(config(), *main.utc_time_window(NOW), post=post)

        self.assertEqual(response, cloudflare_payload([event()]))
        self.assertEqual(calls[0][0], (main.CLOUDFLARE_GRAPHQL_URL,))
        self.assertEqual(calls[0][1]["headers"]["X-Auth-Email"], "user@example.com")
        self.assertEqual(calls[0][1]["json"]["variables"]["zoneTag"], "zone")

    def test_get_blocked_ip_rejects_http_errors(self):
        def post(*args, **kwargs):
            request = httpx.Request("POST", main.CLOUDFLARE_GRAPHQL_URL)
            response = httpx.Response(500, request=request)
            error = httpx.HTTPStatusError("nope", request=request, response=response)
            return FakeResponse(http_error=error)

        with self.assertRaisesRegex(main.ApiError, "Failed to connect to Cloudflare"):
            main.get_blocked_ip(config(), *main.utc_time_window(NOW), post=post)

    def test_get_blocked_ip_rejects_invalid_json(self):
        def post(*args, **kwargs):
            return FakeResponse(json_error=json.JSONDecodeError("bad", "", 0))

        with self.assertRaisesRegex(main.ApiError, "decode JSON response"):
            main.get_blocked_ip(config(), *main.utc_time_window(NOW), post=post)

    def test_get_blocked_ip_rejects_empty_graphql_error_and_missing_data(self):
        with self.assertRaisesRegex(main.ApiError, "Empty response"):
            main.validate_cloudflare_response({})

        with self.assertRaisesRegex(main.ApiError, "non-object JSON"):
            main.validate_cloudflare_response([{"data": {}}])

        with self.assertRaisesRegex(main.ApiError, "returned errors"):
            main.validate_cloudflare_response({"errors": [{"message": "bad"}]})

        with self.assertRaisesRegex(main.ApiError, "'data' key"):
            main.validate_cloudflare_response({"ok": True})

    def test_extract_firewall_events_rejects_bad_shapes(self):
        self.assertEqual(main.extract_firewall_events(cloudflare_payload([event()])), [event()])

        with self.assertRaisesRegex(main.ApiError, "Missing expected key"):
            main.extract_firewall_events({"data": {"viewer": {"zones": []}}})

        with self.assertRaisesRegex(main.ApiError, "not a list"):
            main.extract_firewall_events(
                {
                    "data": {
                        "viewer": {
                            "zones": [
                                {
                                    "firewallEventsAdaptive": "not-list",
                                }
                            ]
                        }
                    }
                }
            )


class CommentAndCategoryTest(unittest.TestCase):
    def test_service_label_known_unknown_and_empty(self):
        self.assertEqual(main.get_service_label("firewallCustom"), "Custom rules")
        self.assertEqual(main.get_service_label("custom_source"), "Custom Source")
        self.assertEqual(main.get_service_label(None), "Unknown service")

    def test_comment_includes_service_and_robots_hint(self):
        comment = main.get_comment(event(source="firewallCustom", clientRequestPath="/wp-json/"))

        self.assertIn("blocked by Custom rules; requester ignored robots.txt", comment)
        self.assertIn("(ASN: 64500)", comment)
        self.assertIn("(Path: /wp-json/)", comment)

    def test_managed_waf_block_is_web_app_attack(self):
        self.assertEqual(main.get_categories(event(source="firewallmanaged")), "21")

    def test_sql_injection_adds_specific_category(self):
        categories = main.get_categories(
            event(clientRequestQuery="id=1 UNION SELECT password FROM users")
        )

        self.assertEqual(categories, "16,21")

    def test_bot_source_is_bad_web_bot(self):
        self.assertEqual(main.get_categories(event(source="botmanagement")), "19")

    def test_bot_user_agent_is_bad_web_bot(self):
        self.assertEqual(
            main.get_categories(event(source="securitylevel", userAgent="sqlmap/1.8")),
            "19",
        )

    def test_web_probe_path_is_web_app_attack(self):
        self.assertEqual(main.get_categories(event(clientRequestPath="/.env")), "21")

    def test_wordpress_rest_probe_is_web_app_attack(self):
        categories = main.get_categories(
            event(
                clientRequestPath="/wordpress/wp-json/",
                clientRequestQuery="?rest_route=/",
            )
        )

        self.assertEqual(categories, "21")

    def test_wordpress_rest_route_probe_is_web_app_attack(self):
        categories = main.get_categories(
            event(
                source="firewallCustom",
                clientRequestPath="/blog/",
                clientRequestQuery="?rest_route=/",
            )
        )

        self.assertEqual(categories, "21")

    def test_wordpress_config_backup_probe_is_web_app_attack(self):
        self.assertEqual(
            main.get_categories(
                event(source="firewallCustom", clientRequestPath="/wp-config.php.bak")
            ),
            "21",
        )

    def test_admin_route_probe_is_web_app_attack(self):
        self.assertEqual(
            main.get_categories(
                event(source="firewallCustom", clientRequestPath="/settings")
            ),
            "21",
        )

    def test_known_crawler_probe_is_not_bad_web_bot_by_name_only(self):
        categories = main.get_categories(
            event(
                source="firewallCustom",
                clientRequestPath="/wp-config.php",
                userAgent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            )
        )

        self.assertEqual(categories, "21")

    def test_post_to_login_path_is_brute_force_and_web_app_attack(self):
        categories = main.get_categories(
            event(clientRequestHTTPMethodName="POST", clientRequestPath="/wp-login.php")
        )

        self.assertEqual(categories, "18,21")

    def test_l7ddos_source_is_ddos_attack(self):
        self.assertEqual(main.get_categories(event(source="l7ddos")), "4")

    def test_unknown_event_falls_back_to_generic_hacking(self):
        self.assertEqual(main.get_categories(event(source="securitylevel")), "15")


class AbuseIpDbTest(unittest.TestCase):
    def test_hash_ip_is_deterministic_with_injected_time_and_pepper(self):
        first = main.hash_ip("203.0.113.9", pepper="pepper", now=NOW)
        second = main.hash_ip("203.0.113.9", pepper="pepper", now=NOW)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_abuseipdb_params_include_categories_comment_and_timestamp(self):
        params = main.abuseipdb_params(event(clientRequestPath="/wp-config.php"))

        self.assertEqual(params["ip"], "203.0.113.9")
        self.assertEqual(params["categories"], "21")
        self.assertEqual(params["timestamp"], "2026-07-30T10:00:00Z")
        self.assertIn("/wp-config.php", params["comment"])

    def test_report_bad_ip_success_logs_hashed_ip(self):
        calls = []

        def post(*args, **kwargs):
            calls.append((args, kwargs))
            return FakeResponse(payload={"data": {"abuseConfidenceScore": 87}})

        output = io.StringIO()
        result = main.report_bad_ip(event(), config(), post=post, output=output, now=NOW)

        self.assertEqual(result, {"abuseConfidenceScore": 87})
        self.assertEqual(calls[0][1]["url"], main.ABUSEIPDB_REPORT_URL)
        self.assertEqual(calls[0][1]["headers"]["Key"], "abuse-key")
        self.assertIn("reported:", output.getvalue())
        self.assertIn("categories: 21", output.getvalue())
        self.assertNotIn("203.0.113.9", output.getvalue())

    def test_report_bad_ip_success_handles_missing_data(self):
        output = io.StringIO()

        result = main.report_bad_ip(
            event(),
            config(),
            post=lambda *args, **kwargs: FakeResponse(payload={}),
            output=output,
            now=NOW,
        )

        self.assertEqual(result, {})
        self.assertIn('"abuseConfidenceScore": "N/A"', output.getvalue())

    def test_report_bad_ip_rejects_request_errors(self):
        def post(*args, **kwargs):
            raise httpx.RequestError("offline")

        with self.assertRaisesRegex(main.ApiError, "Failed to connect to AbuseIPDB"):
            main.report_bad_ip(event(), config(), post=post)

    def test_report_bad_ip_rejects_success_with_invalid_json(self):
        with self.assertRaisesRegex(main.ApiError, "decode JSON response"):
            main.report_bad_ip(
                event(),
                config(),
                post=lambda *args, **kwargs: FakeResponse(
                    json_error=json.JSONDecodeError("bad", "", 0)
                ),
            )

    def test_report_bad_ip_rejects_success_with_non_object_json(self):
        with self.assertRaisesRegex(main.ApiError, "non-object JSON"):
            main.report_bad_ip(
                event(),
                config(),
                post=lambda *args, **kwargs: FakeResponse(payload=[]),
            )

    def test_report_bad_ip_rejects_error_response_and_hashes_ip(self):
        output = io.StringIO()

        with self.assertRaisesRegex(main.ApiError, "HTTP 429"):
            main.report_bad_ip(
                event(),
                config(),
                post=lambda *args, **kwargs: FakeResponse(
                    status_code=429,
                    payload={"data": {"ipAddress": "203.0.113.9", "detail": "duplicate"}},
                ),
                output=output,
                now=NOW,
            )

        self.assertIn("error: 429", output.getvalue())
        self.assertIn("duplicate", output.getvalue())
        self.assertNotIn("203.0.113.9", output.getvalue())

    def test_report_bad_ip_rejects_error_response_with_invalid_json(self):
        output = io.StringIO()

        with self.assertRaisesRegex(main.ApiError, "decode JSON response"):
            main.report_bad_ip(
                event(),
                config(),
                post=lambda *args, **kwargs: FakeResponse(
                    status_code=500,
                    json_error=json.JSONDecodeError("bad", "", 0),
                ),
                output=output,
            )

        self.assertIn("error: 500", output.getvalue())


class RunnerTest(unittest.TestCase):
    def test_should_report_event_filters_expected_cases(self):
        cfg = config()
        self.assertTrue(main.should_report_event(event(), set(), cfg))
        self.assertFalse(main.should_report_event(event(clientIP=""), set(), cfg))
        self.assertFalse(
            main.should_report_event(event(ruleId=main.EXCEPTED_RULE_IDS[0]), set(), cfg)
        )
        self.assertFalse(main.should_report_event(event(clientIP="192.0.2.10"), set(), cfg))
        self.assertFalse(
            main.should_report_event(event(clientIP="203.0.113.9"), {"203.0.113.9"}, cfg)
        )

    def test_process_events_reports_each_ip_once(self):
        reported = []

        def post(*args, **kwargs):
            reported.append(kwargs["params"]["ip"])
            return FakeResponse(payload={"data": {"abuseConfidenceScore": 80}})

        count = main.process_events(
            [
                event(clientIP="203.0.113.9"),
                event(clientIP="203.0.113.9", clientRequestPath="/wp-config.php"),
                event(clientIP="192.0.2.10"),
                event(clientIP="198.51.100.100", ruleId=main.EXCEPTED_RULE_IDS[0]),
                event(clientIP="198.51.100.11"),
            ],
            config(),
            post=post,
            output=io.StringIO(),
            now=NOW,
        )

        self.assertEqual(count, 2)
        self.assertEqual(reported, ["203.0.113.9", "198.51.100.11"])

    def test_run_fetches_events_and_reports_count(self):
        calls = []

        def post(*args, **kwargs):
            calls.append((args, kwargs))
            if args:
                return FakeResponse(
                    payload=cloudflare_payload(
                        [event(clientIP="203.0.113.9"), event(clientIP="203.0.113.10")]
                    )
                )
            return FakeResponse(payload={"data": {"abuseConfidenceScore": 90}})

        output = io.StringIO()
        count = main.run(config(), now=NOW, post=post, output=output)

        self.assertEqual(count, 2)
        self.assertEqual(len(calls), 3)
        self.assertIn("Events from:  2026-07-30T09:45:00Z", output.getvalue())
        self.assertIn("Number of IPs reported to AbuseIPDB: 2", output.getvalue())
        self.assertIn("==================== End ====================", output.getvalue())

    def test_main_returns_failure_for_api_error(self):
        stderr = io.StringIO()
        with (
            mock.patch("main.run", side_effect=main.ApiError("boom")),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = main.main(CONFIG_ENV)

        self.assertEqual(exit_code, 1)
        self.assertIn("boom", stderr.getvalue())

    def test_main_returns_success_when_reports_were_sent(self):
        with mock.patch("main.run", return_value=2):
            exit_code = main.main(CONFIG_ENV)

        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
