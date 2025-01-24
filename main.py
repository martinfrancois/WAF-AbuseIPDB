# This code was documented by the BeeHive Team, to help those seeking to learn.
# This documentation does not impact the function of the code.
# Please do not remove it, so that users who reuse or find this can learn.

# Importing required libraries
import json
import requests
import time
import os
import hashlib
from datetime import datetime

# Accessing environment variables
CLOUDFLARE_ZONE_ID = os.environ["CLOUDFLARE_ZONE_ID"]
CLOUDFLARE_EMAIL = os.environ["CLOUDFLARE_EMAIL"]
CLOUDFLARE_API_KEY = os.environ["CLOUDFLARE_API_KEY"]
ABUSEIPDB_API_KEY = os.environ["ABUSEIPDB_API_KEY"]
PEPPER = os.environ.get("PEPPER", "")
IGNORED_IP_ADDRESSES = os.environ.get("IGNORED_IP_ADDRESSES", "")  # string of IP addresses delimited by a comma

def array_from_string(input_string):
    """Converts a comma-delimited string into a list."""
    return input_string.split(',') if input_string else []

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
    Handles errors gracefully and avoids infinite recursion.
    """
    global ttl
    ttl -= 1
    print("ttl:", ttl)
    if ttl <= 0:
        print("TTL expired. Returning empty list.")
        return {}
    try:
        # Send a POST request to the Cloudflare API with the defined headers and PAYLOAD data
        response = requests.post("https://api.cloudflare.com/client/v4/graphql/", headers=headers, data=PAYLOAD)
        response_json = response.json()
        
        if not response_json:
            print("Empty response received from Cloudflare API.")
            return {}
        
        if 'errors' in response_json:
            print("API returned errors:")
            print(json.dumps(response_json['errors'], indent=4))
            return {}
        
        if 'data' not in response_json:
            print("Unexpected response structure:")
            print(json.dumps(response_json, indent=4))
            return {}
        
        return response_json

    except Exception as e:
        print("Exception occurred while fetching blocked IPs:", e)
        return {}

def get_comment(it):
    """
    Generates a comment for the Bad IP Address report intended for AbuseIPDB.
    """
    return (
        "Unauthorized " + it['clientRequestHTTPProtocol'] + " request, ignoring robots.txt: "
        "(ASN: " + it['clientAsn'] + ") "
        "(Network: " + it['clientASNDescription'] + ") "
        "(Method: " + it['clientRequestHTTPMethodName'] + ") "
        "(Path: " + it['clientRequestPath'] + ") "
        "(Query: " + it['clientRequestQuery'] + ") "
        "(User Agent: " + it['userAgent'] + ")"
    )

def hash_ip(ip):
    """
    Hashes the IP to avoid logging traceable information.
    """
    salt = datetime.now().strftime("%Y-%m-%dT%H")
    combined_string = ip + salt + PEPPER
    hashed = hashlib.sha3_256(combined_string.encode()).hexdigest()
    return hashed

def report_bad_ip(it):
    """
    Reports a bad IP address to AbuseIPDB.
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
        r = requests.post(url=url, headers=headers_abuse, params=params)
        if r.status_code == 200:
            # If response code 200, record a successfully reported IP
            print("Reported:", hash_ip(it['clientIP']))
        else:
            # Otherwise, print the status code as an error
            print("Error reporting IP:", r.status_code)
            # Parse the response data and print it
            try:
                decodedResponse = r.json()
                if "data" in decodedResponse:
                    responseData = decodedResponse["data"]
                    responseData["ipAddress"] = hash_ip(responseData["ipAddress"])
                    print(json.dumps(responseData, sort_keys=True, indent=4))
                else:
                    print("Unexpected response structure from AbuseIPDB:", json.dumps(decodedResponse, indent=4))
            except json.JSONDecodeError:
                print("Failed to decode JSON response from AbuseIPDB.")
    except Exception as e:
        # If there is an exception, print the needed error message to account for it
        print("Exception occurred while reporting bad IP:", e)

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
    ip_bad_list = a["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    print(f"Number of firewall events fetched: {len(ip_bad_list)}")

    reported_ip_list = []
    for i in ip_bad_list:
        if i['ruleId'] not in excepted_ruleId:
            if i['clientIP'] not in reported_ip_list and i['clientIP'] not in ignored_ip_addresses:
                report_bad_ip(i)
                reported_ip_list.append(i['clientIP'])

    print(f"Number of IPs reported to AbuseIPDB: {len(reported_ip_list)}")
else:
    print("No valid data received. Skipping IP reporting.")

print("==================== End ====================")
