# This code was documented by the BeeHive Team, to help those seeking to learn.
# This documentation does not impact the function of the code.
# Please do not remove it, so that users who reuse or find this can learn.

# Importing required libraries
import json
import httpx
import time
import os
import hashlib
import sys
from datetime import datetime, timezone  # Updated import for timezone awareness

# Accessing environment variables
CLOUDFLARE_ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID")
CLOUDFLARE_EMAIL = os.environ.get("CLOUDFLARE_EMAIL")
CLOUDFLARE_API_KEY = os.environ.get("CLOUDFLARE_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
PEPPER = os.environ.get("PEPPER", "")
IGNORED_IP_ADDRESSES = os.environ.get("IGNORED_IP_ADDRESSES", "")  # string of IP addresses delimited by a comma

# Validate essential environment variables
essential_vars = {
    "CLOUDFLARE_ZONE_ID": CLOUDFLARE_ZONE_ID,
    "CLOUDFLARE_EMAIL": CLOUDFLARE_EMAIL,
    "CLOUDFLARE_API_KEY": CLOUDFLARE_API_KEY,
    "ABUSEIPDB_API_KEY": ABUSEIPDB_API_KEY
}

missing_vars = [var for var, value in essential_vars.items() if not value]
if missing_vars:
    print(f"Error: Missing essential environment variables: {', '.join(missing_vars)}", file=sys.stderr)
    sys.exit(1)

def array_from_string(input_string):
    """Converts a comma-delimited string into a list."""
    return [ip.strip() for ip in input_string.split(',')] if input_string else []

# Define the time range for fetching firewall events
rangeFrom = time.localtime(time.time() - 60 * 60 * 2.5)  # 2.5 hours ago
rangeUntil = time.localtime(time.time())  # Current time
ignored_ip_addresses = array_from_string(IGNORED_IP_ADDRESSES)

# Set payload for Cloudflare API requests with corrected GraphQL query
PAYLOAD = {
    "query": """query ListFirewallEvents($zoneTag: String!, $filter: FirewallEventsAdaptiveFilter_InputObject!) {
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
    }""",
    "variables": {
        "zoneTag": CLOUDFLARE_ZONE_ID,
        "filter": {
            "datetime_geq": time.strftime("%Y-%m-%dT%H:%M:%SZ", rangeFrom),
            "datetime_leq": time.strftime("%Y-%m-%dT%H:%M:%SZ", rangeUntil),
            "AND": [
                {"action_neq": "allow"},
                {"action_neq": "skip"},
                {"action_neq": "challenge_solved"},
                {"action_neq": "challenge_failed"},
                {"action_neq": "challenge_bypassed"},
                {"action_neq": "jschallenge_solved"},
                {"action_neq": "jschallenge_failed"},
                {"action_neq": "jschallenge_bypassed"},
                {"action_neq": "managed_challenge_skipped"},
                {"action_neq": "managed_challenge_non_interactive_solved"},
                {"action_neq": "managed_challenge_interactive_solved"},
                {"action_neq": "managed_challenge_bypassed"},
            ]
        }
    }
}

# Convert PAYLOAD dictionary to a JSON string
PAYLOAD = json.dumps(PAYLOAD)

# Define headers for the API request
headers = {
    "Content-Type": "application/json",
    "X-Auth-Key": CLOUDFLARE_API_KEY,
    "X-Auth-Email": CLOUDFLARE_EMAIL
}

# Set the initial time to live value to 60
ttl = 60

def get_blocked_ip():
    """
    Retrieves blocked IP addresses from Cloudflare's GraphQL API.
    Exits the script with status code 1 if it fails to fetch data.
    """
    global ttl
    ttl -= 1
    print("ttl:", ttl)
    if ttl <= 0:
        print("TTL expired. Exiting script due to repeated failures.", file=sys.stderr)
        sys.exit(1)
    try:
        # Send a POST request to the Cloudflare API with the defined headers and PAYLOAD data
        response = httpx.post(
            "https://api.cloudflare.com/client/v4/graphql/",
            headers=headers,
            content=PAYLOAD,
        )
        response.raise_for_status()  # Raises HTTPError for bad HTTP status codes
        response_json = response.json()

        if not response_json:
            print("Error: Empty response received from Cloudflare API.", file=sys.stderr)
            sys.exit(1)

        # Check if 'errors' key exists and contains non-empty list
        if 'errors' in response_json and response_json['errors']:
            print("Error: Cloudflare API returned errors:", file=sys.stderr)
            print(json.dumps(response_json['errors'], indent=4), file=sys.stderr)
            sys.exit(1)

        # Ensure 'data' key exists
        if 'data' not in response_json:
            print("Error: 'data' key not found in Cloudflare API response.", file=sys.stderr)
            print(json.dumps(response_json, indent=4), file=sys.stderr)
            sys.exit(1)

        return response_json

    except httpx.RequestError as e:
        print(f"Error: Failed to connect to Cloudflare API: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON response from Cloudflare API.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error while fetching blocked IPs: {e}", file=sys.stderr)
        sys.exit(1)

def get_service_label(source: str | None) -> str:
    """
    Map Cloudflare firewall event 'source' to the friendly 'Service' name
    shown in the Security Events dashboard.
    Falls back to a humanized version of the raw code.
    """
    if not source:
        return "Unknown service"

    key = source.strip().lower()  # normalize case for mapping

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

    return mapping.get(key, key.replace("_", " ").title())

def get_comment(it):
    """
    Generates a comment for the Bad IP Address report intended for AbuseIPDB.
    Includes the Cloudflare security 'Service' that blocked the request.
    """
    service = get_service_label(it.get("source"))
    source_code = (it.get("source") or "").lower()
    robots_hint = "; requester ignored robots.txt" if source_code in ("firewallcustom", "firewallrules") else ""
    return (
        f"Unauthorized {it['clientRequestHTTPProtocol']} {it['clientRequestHTTPMethodName']} {it['clientRequestPath']} "
        f"blocked by {service}{robots_hint}: "
        f"(ASN: {it['clientAsn']}) "
        f"(Network: {it['clientASNDescription']}) "
        f"(Method: {it['clientRequestHTTPMethodName']}) "
        f"(Path: {it['clientRequestPath']}) "
        f"(Query: {it['clientRequestQuery']}) "
        f"(User Agent: {it['userAgent']})"
    )

def hash_ip(ip):
    """
    Hashes the IP to avoid logging traceable information.
    """
    # Use timezone-aware datetime
    salt = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
    combined_string = ip + salt + PEPPER
    hashed = hashlib.sha3_256(combined_string.encode()).hexdigest()
    return hashed

def report_bad_ip(it):
    """
    Reports a bad IP address to AbuseIPDB and logs the abuseConfidenceScore.
    Exits the script with status code 1 if reporting fails.
    """
    try:
        url = 'https://api.abuseipdb.com/api/v2/report'
        params = {
            'ip': it['clientIP'],
            'categories': '14,15,16,19,20,21',
            'comment': get_comment(it),
            'timestamp': it['datetime']
        }
        headers_abuse = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        # Send a POST request to the AbuseIPDB API with the required contents
        r = httpx.post(url=url, headers=headers_abuse, params=params)

        if r.status_code == 200:
            # If response code 200, record a successfully reported IP
            hashed_ip = hash_ip(it['clientIP'])
            print("reported:", hashed_ip)
            try:
                decodedResponse = r.json()
                responseData = decodedResponse.get("data", {})
                abuse_confidence_score = responseData.get("abuseConfidenceScore", "N/A")
                print(json.dumps({
                    "abuseConfidenceScore": abuse_confidence_score,
                    "ipAddress": hashed_ip
                }, indent=4))
            except json.JSONDecodeError:
                print("Error: Failed to decode JSON response from AbuseIPDB.", file=sys.stderr)
                sys.exit(1)
        else:
            # Otherwise, print the status code as an error
            print("error:", r.status_code)
            try:
                decodedResponse = r.json()
                responseData = decodedResponse.get("data", {})
                if "ipAddress" in responseData:
                    responseData["ipAddress"] = hash_ip(responseData["ipAddress"])
                print(json.dumps(responseData, sort_keys=True, indent=4))
            except json.JSONDecodeError:
                print("error: Failed to decode JSON response from AbuseIPDB.", file=sys.stderr)
            sys.exit(1)

    except httpx.RequestError as e:
        print(f"Error: Failed to connect to AbuseIPDB API: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON response from AbuseIPDB API.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error while reporting bad IP: {e}", file=sys.stderr)
        sys.exit(1)

# Define a list of excluded Cloudflare WAF Rule IDs
excepted_ruleId = ["fa01280809254f82978e827892db4e46"]

# Print start time and end time within output
print("==================== Start ====================")
print("Events from:  " + str(time.strftime("%Y-%m-%d %H:%M:%S", rangeFrom)))
print("Events until: " + str(time.strftime("%Y-%m-%d %H:%M:%S", rangeUntil)))

# Fetch blocked IP data
a = get_blocked_ip()

# Process the fetched data if it's a valid dictionary with content
if isinstance(a, dict) and a:
    try:
        ip_bad_list = a["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
        print(f"Number of firewall events fetched: {len(ip_bad_list)}")

        reported_ip_list = []
        for i in ip_bad_list:
            if i['ruleId'] not in excepted_ruleId:
                if i['clientIP'] not in reported_ip_list and i['clientIP'] not in ignored_ip_addresses:
                    report_bad_ip(i)
                    reported_ip_list.append(i['clientIP'])

        print(f"Number of IPs reported to AbuseIPDB: {len(reported_ip_list)}")
    except KeyError as e:
        print(f"Error: Missing expected key in Cloudflare API response: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error while processing firewall events: {e}", file=sys.stderr)
        sys.exit(1)
else:
    print("Error: No valid data received from Cloudflare API. Exiting.", file=sys.stderr)
    sys.exit(1)

print("==================== End ====================")
