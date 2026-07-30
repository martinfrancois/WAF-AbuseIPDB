import hashlib
import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TextIO

import httpx

CLOUDFLARE_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql/"
ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
REPORT_LOOKBACK = timedelta(hours=2, minutes=30)

CLOUDFLARE_QUERY = """
query ListFirewallEvents(
    $zoneTag: String!
    $filter: FirewallEventsAdaptiveFilter_InputObject!
) {
    viewer {
        zones(filter: { zoneTag: $zoneTag }) {
            firewallEventsAdaptive(
                filter: $filter
                limit: 2500
                orderBy: [datetime_DESC]
            ) {
                action
                clientASNDescription
                clientAsn
                clientCountryName
                clientIP
                clientRequestHTTPHost
                clientRequestHTTPMethodName
                clientRequestHTTPProtocol
                clientRequestPath
                clientRequestQuery
                datetime
                rayName
                ruleId
                source
                userAgent
            }
        }
    }
}"""

EXCLUDED_ACTIONS = (
    "allow",
    "skip",
    "challenge_solved",
    "challenge_failed",
    "challenge_bypassed",
    "jschallenge_solved",
    "jschallenge_failed",
    "jschallenge_bypassed",
    "managed_challenge_skipped",
    "managed_challenge_non_interactive_solved",
    "managed_challenge_interactive_solved",
    "managed_challenge_bypassed",
)

EXCEPTED_RULE_IDS = ("fa01280809254f82978e827892db4e46",)

ABUSEIPDB_CATEGORY = {
    "DDOS_ATTACK": "4",
    "HACKING": "15",
    "SQL_INJECTION": "16",
    "BRUTE_FORCE": "18",
    "BAD_WEB_BOT": "19",
    "WEB_APP_ATTACK": "21",
}

SQL_INJECTION_PATTERNS = (
    r"\bunion\s+(?:all\s+)?select\b",
    r"\binformation_schema\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
    r"(?:'|%27|\")\s*(?:or|and)\s+(?:'?\w+'?\s*=\s*'?\w+'?|[0-9]+\s*=\s*[0-9]+)",
)

WEB_APP_PROBE_MARKERS = (
    ".env",
    "/.git/",
    "wp-config",
    "wp-login.php",
    "xmlrpc.php",
    "wp-json",
    "wp-admin",
    "wp-content",
    "/wp/",
    "/wordpress/",
    "/cms/",
    "/blog/",
    "/site/",
    "rest_route=/",
    "phpmyadmin",
    "/admin",
    "/administrator",
    "/control",
    "/settings",
    "/server/",
    "/config",
    "/backup",
    "/debug",
    "/vendor/phpunit",
    "etc/passwd",
    "../",
    "%2e%2e%2f",
)

LOGIN_PATH_MARKERS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "session",
    "wp-login.php",
    "xmlrpc.php",
)

BOT_USER_AGENT_MARKERS = (
    "scrapy",
    "curl",
    "wget",
    "python-requests",
    "python-httpx",
    "go-http-client",
    "masscan",
    "nikto",
    "sqlmap",
)

KNOWN_CRAWLER_USER_AGENT_MARKERS = (
    "bingbot",
    "googlebot",
    "gptbot",
    "chatgpt-user",
    "xai-searchbot",
)


class ConfigError(ValueError):
    pass


class ApiError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    cloudflare_zone_id: str
    cloudflare_email: str
    cloudflare_api_key: str
    abuseipdb_api_key: str
    pepper: str = ""
    ignored_ip_addresses: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "Config":
        values = os.environ if environ is None else environ
        required = {
            "CLOUDFLARE_ZONE_ID": values.get("CLOUDFLARE_ZONE_ID"),
            "CLOUDFLARE_EMAIL": values.get("CLOUDFLARE_EMAIL"),
            "CLOUDFLARE_API_KEY": values.get("CLOUDFLARE_API_KEY"),
            "ABUSEIPDB_API_KEY": values.get("ABUSEIPDB_API_KEY"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ConfigError(
                f"Missing essential environment variables: {', '.join(missing)}"
            )

        return cls(
            cloudflare_zone_id=required["CLOUDFLARE_ZONE_ID"] or "",
            cloudflare_email=required["CLOUDFLARE_EMAIL"] or "",
            cloudflare_api_key=required["CLOUDFLARE_API_KEY"] or "",
            abuseipdb_api_key=required["ABUSEIPDB_API_KEY"] or "",
            pepper=values.get("PEPPER", ""),
            ignored_ip_addresses=tuple(
                array_from_string(values.get("IGNORED_IP_ADDRESSES", ""))
            ),
        )


def array_from_string(input_string: str) -> list[str]:
    return [value.strip() for value in input_string.split(",") if value.strip()]


def utc_time_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    until = now or datetime.now(UTC)
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    return until - REPORT_LOOKBACK, until


def cloudflare_datetime(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_cloudflare_payload(
    config: Config, range_from: datetime, range_until: datetime
) -> dict[str, Any]:
    return {
        "query": CLOUDFLARE_QUERY,
        "variables": {
            "zoneTag": config.cloudflare_zone_id,
            "filter": {
                "datetime_geq": cloudflare_datetime(range_from),
                "datetime_leq": cloudflare_datetime(range_until),
                "AND": [{"action_neq": action} for action in EXCLUDED_ACTIONS],
            },
        },
    }


def cloudflare_headers(config: Config) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Auth-Key": config.cloudflare_api_key,
        "X-Auth-Email": config.cloudflare_email,
    }


def validate_cloudflare_response(response_json: dict[str, Any]) -> dict[str, Any]:
    if not response_json:
        raise ApiError("Empty response received from Cloudflare API.")
    if response_json.get("errors"):
        raise ApiError(
            "Cloudflare API returned errors: "
            + json.dumps(response_json["errors"], indent=4)
        )
    if "data" not in response_json:
        raise ApiError(
            "'data' key not found in Cloudflare API response: "
            + json.dumps(response_json, indent=4)
        )
    return response_json


def get_blocked_ip(
    config: Config,
    range_from: datetime,
    range_until: datetime,
    post: Callable[..., httpx.Response] = httpx.post,
) -> dict[str, Any]:
    try:
        response = post(
            CLOUDFLARE_GRAPHQL_URL,
            headers=cloudflare_headers(config),
            json=build_cloudflare_payload(config, range_from, range_until),
        )
        response.raise_for_status()
        return validate_cloudflare_response(response.json())
    except httpx.HTTPError as exc:
        raise ApiError(f"Failed to connect to Cloudflare API: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ApiError("Failed to decode JSON response from Cloudflare API.") from exc


def extract_firewall_events(response_json: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        events = response_json["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ApiError(f"Missing expected key in Cloudflare API response: {exc}") from exc
    if not isinstance(events, list):
        raise ApiError("Cloudflare firewall events response is not a list.")
    return events


def get_service_label(source: str | None) -> str:
    if not source:
        return "Unknown service"

    mapping = {
        "firewallmanaged": "Managed rules",
        "firewallcustom": "Custom rules",
        "firewallrules": "Custom rules",
        "bic": "Browser Integrity Check",
        "ratelimit": "Rate limiting",
        "waf": "WAF (legacy managed rules)",
        "botmanagement": "Bot Management",
        "botfight": "Bot Fight Mode",
        "apishield": "API Shield",
        "apishieldschemavalidation": "API Shield schema validation",
        "apishieldtokenvalidation": "API Shield token validation",
        "apishieldsequencemitigation": "API Shield sequence mitigation",
        "l7ddos": "HTTP DDoS protection",
        "validation": "HTTP request validation",
        "uablock": "User Agent Blocking",
        "securitylevel": "Security Level",
        "zonelockdown": "Zone Lockdown",
        "asn": "IP Access rules (ASN)",
        "country": "IP Access rules (Country)",
        "ip": "IP Access rules (IP)",
        "iprange": "IP Access rules (IP range)",
        "hot": "HOT",
    }
    return mapping.get(source.strip().lower(), source.strip().replace("_", " ").title())


def get_comment(event: dict[str, Any]) -> str:
    service = get_service_label(event.get("source"))
    source_code = (event.get("source") or "").lower()
    robots_hint = (
        "; requester ignored robots.txt"
        if source_code in ("firewallcustom", "firewallrules")
        else ""
    )
    return (
        f"Unauthorized {event.get('clientRequestHTTPProtocol', '')} "
        f"{event.get('clientRequestHTTPMethodName', '')} "
        f"{event.get('clientRequestPath', '')} blocked by {service}{robots_hint}: "
        f"(ASN: {event.get('clientAsn', '')}) "
        f"(Network: {event.get('clientASNDescription', '')}) "
        f"(Method: {event.get('clientRequestHTTPMethodName', '')}) "
        f"(Path: {event.get('clientRequestPath', '')}) "
        f"(Query: {event.get('clientRequestQuery', '')}) "
        f"(User Agent: {event.get('userAgent', '')})"
    )


def _event_text(event: dict[str, Any]) -> str:
    return " ".join(
        str(event.get(field) or "")
        for field in ("clientRequestPath", "clientRequestQuery", "userAgent")
    ).lower()


def _matches_any_regex(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


def _contains_any(markers: tuple[str, ...], text: str) -> bool:
    return any(marker in text for marker in markers)


def _is_known_crawler(user_agent: str) -> bool:
    return _contains_any(KNOWN_CRAWLER_USER_AGENT_MARKERS, user_agent)


def get_categories(event: dict[str, Any]) -> str:
    source = (event.get("source") or "").strip().lower()
    method = (event.get("clientRequestHTTPMethodName") or "").strip().upper()
    path = (event.get("clientRequestPath") or "").lower()
    user_agent = (event.get("userAgent") or "").lower()
    text = _event_text(event)

    categories = set()

    if source == "l7ddos":
        categories.add(ABUSEIPDB_CATEGORY["DDOS_ATTACK"])

    if source in {"botmanagement", "botfight", "bic", "uablock"} or (
        not _is_known_crawler(user_agent)
        and _contains_any(BOT_USER_AGENT_MARKERS, user_agent)
    ):
        categories.add(ABUSEIPDB_CATEGORY["BAD_WEB_BOT"])

    if source in {
        "apishield",
        "apishieldschemavalidation",
        "apishieldtokenvalidation",
        "apishieldsequencemitigation",
        "firewallmanaged",
        "validation",
        "waf",
    }:
        categories.add(ABUSEIPDB_CATEGORY["WEB_APP_ATTACK"])

    if _matches_any_regex(SQL_INJECTION_PATTERNS, text):
        categories.add(ABUSEIPDB_CATEGORY["SQL_INJECTION"])
        categories.add(ABUSEIPDB_CATEGORY["WEB_APP_ATTACK"])

    if _contains_any(WEB_APP_PROBE_MARKERS, text):
        categories.add(ABUSEIPDB_CATEGORY["WEB_APP_ATTACK"])

    if method == "POST" and _contains_any(LOGIN_PATH_MARKERS, path):
        categories.add(ABUSEIPDB_CATEGORY["BRUTE_FORCE"])
        categories.add(ABUSEIPDB_CATEGORY["WEB_APP_ATTACK"])

    if not categories:
        categories.add(ABUSEIPDB_CATEGORY["HACKING"])

    return ",".join(sorted(categories, key=int))


def hash_ip(ip: str, pepper: str = "", now: datetime | None = None) -> str:
    timestamp = now or datetime.now(UTC)
    salt = timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H")
    return hashlib.sha3_256(f"{ip}{salt}{pepper}".encode()).hexdigest()


def abuseipdb_headers(config: Config) -> dict[str, str]:
    return {"Accept": "application/json", "Key": config.abuseipdb_api_key}


def abuseipdb_params(event: dict[str, Any]) -> dict[str, str]:
    return {
        "ip": event["clientIP"],
        "categories": get_categories(event),
        "comment": get_comment(event),
        "timestamp": event["datetime"],
    }


def decode_response_json(response: httpx.Response, service: str) -> dict[str, Any]:
    try:
        decoded = response.json()
    except json.JSONDecodeError as exc:
        raise ApiError(f"Failed to decode JSON response from {service}.") from exc
    if not isinstance(decoded, dict):
        raise ApiError(f"{service} returned a non-object JSON response.")
    return decoded


def report_bad_ip(
    event: dict[str, Any],
    config: Config,
    post: Callable[..., httpx.Response] = httpx.post,
    output: TextIO = sys.stdout,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        response = post(
            url=ABUSEIPDB_REPORT_URL,
            headers=abuseipdb_headers(config),
            params=abuseipdb_params(event),
        )
    except httpx.RequestError as exc:
        raise ApiError(f"Failed to connect to AbuseIPDB API: {exc}") from exc

    hashed_ip = hash_ip(event["clientIP"], config.pepper, now)
    if response.status_code == 200:
        decoded = decode_response_json(response, "AbuseIPDB")
        response_data = decoded.get("data", {})
        print(f"reported: {hashed_ip}", file=output)
        print(f"categories: {get_categories(event)}", file=output)
        print(
            json.dumps(
                {
                    "abuseConfidenceScore": response_data.get(
                        "abuseConfidenceScore", "N/A"
                    ),
                    "ipAddress": hashed_ip,
                },
                indent=4,
            ),
            file=output,
        )
        return response_data

    print(f"error: {response.status_code}", file=output)
    try:
        response_data = decode_response_json(response, "AbuseIPDB").get("data", {})
    except ApiError as exc:
        print(f"error: {exc}", file=output)
        raise
    if "ipAddress" in response_data:
        response_data["ipAddress"] = hash_ip(response_data["ipAddress"], config.pepper, now)
    print(json.dumps(response_data, sort_keys=True, indent=4), file=output)
    raise ApiError(f"AbuseIPDB report failed with HTTP {response.status_code}.")


def should_report_event(
    event: dict[str, Any], reported_ips: set[str], config: Config
) -> bool:
    client_ip = event.get("clientIP")
    return (
        bool(client_ip)
        and event.get("ruleId") not in EXCEPTED_RULE_IDS
        and client_ip not in reported_ips
        and client_ip not in config.ignored_ip_addresses
    )


def process_events(
    events: list[dict[str, Any]],
    config: Config,
    post: Callable[..., httpx.Response] = httpx.post,
    output: TextIO = sys.stdout,
    now: datetime | None = None,
) -> int:
    reported_ips: set[str] = set()
    for event in events:
        client_ip = event.get("clientIP")
        if should_report_event(event, reported_ips, config):
            report_bad_ip(event, config, post=post, output=output, now=now)
            reported_ips.add(client_ip)
    return len(reported_ips)


def run(
    config: Config,
    now: datetime | None = None,
    post: Callable[..., httpx.Response] = httpx.post,
    output: TextIO = sys.stdout,
) -> int:
    range_from, range_until = utc_time_window(now)
    print("==================== Start ====================", file=output)
    print(f"Events from:  {cloudflare_datetime(range_from)}", file=output)
    print(f"Events until: {cloudflare_datetime(range_until)}", file=output)

    response_json = get_blocked_ip(config, range_from, range_until, post=post)
    events = extract_firewall_events(response_json)
    print(f"Number of firewall events fetched: {len(events)}", file=output)
    reported_count = process_events(events, config, post=post, output=output, now=now)
    print(f"Number of IPs reported to AbuseIPDB: {reported_count}", file=output)
    print("==================== End ====================", file=output)
    return reported_count


def main(environ: dict[str, str] | None = None) -> int:
    try:
        return run(Config.from_env(environ))
    except (ConfigError, ApiError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
