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

CLOUDFLARE_ZONE_ID = os.environ["CLOUDFLARE_ZONE_ID"]
CLOUDFLARE_EMAIL = os.environ["CLOUDFLARE_EMAIL"]
CLOUDFLARE_API_KEY = os.environ["CLOUDFLARE_API_KEY"]
ABUSEIPDB_API_KEY = os.environ["ABUSEIPDB_API_KEY"]
PEPPER = os.environ.get("PEPPER", "")
IGNORED_IP_ADDRESSES = os.environ.get("IGNORED_IP_ADDRESSES", "")  # string of IP addresses delimited by a comma

def array_from_string(input_string):
    return input_string.split(',') if input_string else []

rangeFrom = time.localtime(time.time()-60*60*2.5)
rangeUntil = time.localtime(time.time())
ignored_ip_addresses = array_from_string(IGNORED_IP_ADDRESSES)

# Set payload for Cloudflare API requests
PAYLOAD={
  "query": """query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {
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
      # "OR":[{"action": "block"}, {"action": "managed_challenge"}, {"action": "jschallenge"}],
      "AND":[
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
headers={"Content-Type":"application/json","X-Auth-Key":CLOUDFLARE_API_KEY,"X-Auth-Email":CLOUDFLARE_EMAIL}
# Set the initial time to live value to 60
ttl=60
# Define a function to get a list of blocked IP Addresses
def get_blocked_ip():
    # Access global variable ttl
  global ttl
  # Decrement ttl by 1
  ttl=ttl-1
  # Print the current value of TTL
  print("ttl:",ttl)
  # If TTL reaches 0, return an empty list
  if ttl<=0:
    return []
  try:
      # Send a POST request to the Cloudflare API with the defined headers and PAYLOAD data
    r=requests.post("https://api.cloudflare.com/client/v4/graphql/",headers=headers,data=PAYLOAD)
    # If the response is None, call the function recursively
    if str(type(r.json())) == "<class 'NoneType'>":
      get_blocked_ip()
    else:
        # Otherwise return JSON response data
      return r.json()
  except Exception as e:
      # If there is an exception, call the function recursively
    get_blocked_ip()

# Define a function to generate a comment for the Bad IP Address report intended for AbuseIPDB
def get_comment(it):
  return "Unauthorized " + it['clientRequestHTTPProtocol'] + " request, ignoring robots.txt: (ASN: "+it['clientAsn']+") (Network: "+it['clientASNDescription']+") (Method: "+it['clientRequestHTTPMethodName']+") (Path: "+it['clientRequestPath']+") (Query: "+it['clientRequestQuery']+") (User Agent: "+it['userAgent']+")"

# Define a function to hash the IP, to avoid logging traceable information
def hash_ip(ip):
  salt = datetime.now().strftime("%Y-%m-%dT%H")
  combined_string = ip + salt + PEPPER
  hashed = hashlib.sha3_256(combined_string.encode()).hexdigest()
  return hashed

# Define a function to report a bad IP address to AbuseIPDB
def report_bad_ip(it):
  try:
    url = 'https://api.abuseipdb.com/api/v2/report'
    params = {
      'ip': it['clientIP'],
      'categories': '9,13,14,15,16,19,20,21',
      'comment': get_comment(it),
      'timestamp': it['datetime']
    }
    headers = {
      'Accept': 'application/json',
      'Key': ABUSEIPDB_API_KEY
    }
    # Send a POST request to the AbuseIPDB API with the required contents
    r=requests.post(url=url, headers=headers, params=params)
    if r.status_code==200:
        # If response code 200, record a successfully reported IP
      print("reported:",hash_ip(it['clientIP']))
    else:
        # Otherwise, print the status code as an error
      print("error:",r.status_code)
      # Parse the response data and print it
    decodedResponse = json.loads(r.text)
    responseData = decodedResponse["data"]
    responseData["ipAddress"] = hash_ip(responseData["ipAddress"])
    print(json.dumps(responseData, sort_keys=True, indent=4))
  except Exception as e:
      # If there is an exception, print the needed error message to account for it
    print("error:",e)

# Define a list of excluded Cloudflare WAF Rule IDs
excepted_ruleId = ["fa01280809254f82978e827892db4e46"]

# Print start time and end time within output
print("==================== Start ====================")
print("Events from:  " + str(time.strftime("%Y-%m-%d %H:%M:%S", rangeFrom)))
print("Events until: " + str(time.strftime("%Y-%m-%d %H:%M:%S", rangeUntil)))
a=get_blocked_ip()
if isinstance(a, dict) and len(a)>0:
  ip_bad_list=a["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
  print(len(ip_bad_list))

  reported_ip_list=[]
  for i in ip_bad_list:
    if i['ruleId'] not in excepted_ruleId:
      if i['clientIP'] not in reported_ip_list and i['clientIP'] not in ignored_ip_addresses:
        report_bad_ip(i)
        reported_ip_list.append(i['clientIP'])

  print(len(reported_ip_list))
print("==================== End ====================")
