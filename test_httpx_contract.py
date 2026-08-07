"""Contract tests that exercise the real httpx request and response machinery.

The rest of the suite injects hand-rolled fakes for the `post` callable, so it
passes even against an httpx that cannot make a request. These tests drive a real
`httpx.Client` through `httpx.MockTransport`, which runs httpx's own URL building,
query-parameter serialisation, header handling, JSON encoding, `raise_for_status`
and `.json()` decoding without touching the network. A breaking change in any of
those surfaces fails here rather than in production.
"""

import io
import json
import unittest
from datetime import UTC, datetime

import httpx

import main

CONFIG_ENV = {
    "CLOUDFLARE_ZONE_ID": "zone",
    "CLOUDFLARE_EMAIL": "user@example.com",
    "CLOUDFLARE_API_KEY": "cloudflare-key",
    "ABUSEIPDB_API_KEY": "abuse-key",
    "PEPPER": "pepper",
    "IGNORED_IP_ADDRESSES": "",
}

NOW = datetime(2026, 7, 30, 12, 15, 0, tzinfo=UTC)
RANGE_FROM = datetime(2026, 7, 30, 10, 0, 0, tzinfo=UTC)
RANGE_UNTIL = datetime(2026, 7, 30, 12, 0, 0, tzinfo=UTC)


def config():
    return main.Config.from_env(dict(CONFIG_ENV))


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


def cloudflare_payload(events=()):
    return {
        "data": {"viewer": {"zones": [{"firewallEventsAdaptive": list(events)}]}}
    }


def client_post(handler):
    """A real httpx.Client.post bound to a mock transport.

    Returns the same callable shape main.py expects for its `post` parameter, so
    the production call site is exercised verbatim.
    """
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return client.post


class CloudflareHttpxContractTest(unittest.TestCase):
    def test_request_is_built_by_real_httpx(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["url"] = str(request.url)
            seen["headers"] = request.headers
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json=cloudflare_payload())

        main.get_blocked_ip(
            config(), RANGE_FROM, RANGE_UNTIL, post=client_post(handler)
        )

        # main.py passes the URL positionally with headers= and json=; if httpx
        # renames or reorders those parameters this call raises instead.
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["url"], main.CLOUDFLARE_GRAPHQL_URL)
        self.assertEqual(seen["headers"]["x-auth-key"], "cloudflare-key")
        self.assertEqual(seen["headers"]["x-auth-email"], "user@example.com")
        self.assertEqual(seen["headers"]["content-type"], "application/json")
        # Real httpx serialised the dict body to JSON bytes.
        self.assertIn("query", seen["body"])
        self.assertEqual(seen["body"]["variables"]["zoneTag"], "zone")

    def test_real_raise_for_status_is_converted_to_api_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="upstream exploded")

        with self.assertRaises(main.ApiError) as caught:
            main.get_blocked_ip(
                config(), RANGE_FROM, RANGE_UNTIL, post=client_post(handler)
            )

        # httpx.HTTPStatusError must remain a subclass of httpx.HTTPError for
        # main.py's except clause to catch it.
        self.assertIn("Failed to connect to Cloudflare API", str(caught.exception))

    def test_real_json_decoding_of_a_malformed_body_is_converted(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="{not json")

        with self.assertRaises(main.ApiError) as caught:
            main.get_blocked_ip(
                config(), RANGE_FROM, RANGE_UNTIL, post=client_post(handler)
            )

        self.assertIn("Failed to decode JSON", str(caught.exception))

    def test_transport_level_failure_is_converted(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host", request=request)

        with self.assertRaises(main.ApiError) as caught:
            main.get_blocked_ip(
                config(), RANGE_FROM, RANGE_UNTIL, post=client_post(handler)
            )

        self.assertIn("Failed to connect to Cloudflare API", str(caught.exception))


class AbuseIpdbHttpxContractTest(unittest.TestCase):
    def test_query_parameters_are_serialised_by_real_httpx(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            seen["params"] = dict(request.url.params)
            seen["headers"] = request.headers
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 42}})

        target = event()
        main.report_bad_ip(
            target,
            config(),
            post=client_post(handler),
            output=io.StringIO(),
            now=NOW,
        )

        # main.py passes url= as a keyword here, unlike the Cloudflare call site.
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["headers"]["key"], "abuse-key")
        self.assertEqual(seen["headers"]["accept"], "application/json")
        # Real httpx URL-encoded the params dict; the comment contains characters
        # that must survive encoding.
        expected = main.abuseipdb_params(target)
        self.assertEqual(seen["params"], expected)

    def test_non_200_status_is_read_from_a_real_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"errors": [{"detail": "slow down"}]})

        # status_code is read off a real httpx.Response, not a hand-rolled fake.
        with self.assertRaises(main.ApiError) as caught:
            main.report_bad_ip(
                event(),
                config(),
                post=client_post(handler),
                output=io.StringIO(),
                now=NOW,
            )

        self.assertIn("HTTP 429", str(caught.exception))

    def test_successful_report_decodes_a_real_json_body(self):
        output = io.StringIO()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 42}})

        main.report_bad_ip(
            event(),
            config(),
            post=client_post(handler),
            output=output,
            now=NOW,
        )

        # decode_response_json ran against a real httpx.Response.
        self.assertIn("abuseConfidenceScore", output.getvalue())
        self.assertIn("42", output.getvalue())


class HttpxSymbolContractTest(unittest.TestCase):
    """Pin the httpx surface main.py depends on, so a removal fails loudly."""

    def test_exception_hierarchy(self):
        self.assertTrue(issubclass(httpx.HTTPStatusError, httpx.HTTPError))
        self.assertTrue(issubclass(httpx.RequestError, httpx.HTTPError))
        self.assertTrue(issubclass(httpx.ConnectError, httpx.RequestError))
        self.assertTrue(issubclass(httpx.TimeoutException, httpx.RequestError))

    def test_module_level_post_exists(self):
        # main.py evaluates httpx.post as a default argument at import time.
        self.assertTrue(callable(httpx.post))


if __name__ == "__main__":
    unittest.main()
