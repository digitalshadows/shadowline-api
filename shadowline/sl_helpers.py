import re
import json
import requests
import sys
import validators

from pprint import pprint
from pandas.io.json import json_normalize
from . import sl_constants
from netaddr import IPAddress, IPNetwork
from pygments import highlight, lexers, formatters
from retrying import retry

def handle_json_output(json_input, raw):
    if raw:
        raw_json = json.dumps(json_input)
        print(raw_json)
    else:                        
        formatted_json = json.dumps(json_input, sort_keys=True, indent=4)
        colorful_json = highlight(formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter())
        print(colorful_json)


def is_ipaddr(ip):
    try:
        tmp_ip = IPAddress(ip)
        if tmp_ip.is_unicast():
            return True

    except Exception as e:
        print("{} is not a valid IP: {}".format(ip, e))
        return False


def is_netrange(cidr):
    try:
        IPNetwork(cidr)
        return True
    except Exception as e:
        print("{} is not a valid IP Network range: {}".format(cidr, e))
        return False

def is_cve(cve):
    exp = '[C][V][E][-]\d\d\d\d[-]\d\d\d\d'
    p = re.compile(exp)
    if p.match(cve):
        return True
    else:
        return False
    
def retry_if_requests_error(exception):
    return isinstance(exception, requests.exceptions.ConnectionError)

@retry(wait_exponential_multiplier=1000, wait_exponential_max=100000, retry_on_exception=retry_if_requests_error)    
def api_call(endpoint,cmd, settings, api_filter=None):
    s = requests.Session()

    s.auth = (settings.USERNAME, settings.PASSWORD)
    
    response = ""

    api_url = "{}{}".format(sl_constants.API_URL, endpoint)

    if validators.url(api_url):
        try:
            if cmd == 'get':
                if api_filter:
                    response = s.get(api_url, headers=sl_constants.HEADERS, json=api_filter)
                else:
                    response = s.get(api_url, headers=sl_constants.HEADERS)
            elif cmd == 'post':
                if api_filter:
                    response = s.post(api_url, headers=sl_constants.HEADERS, json=api_filter)                
        except (requests.exceptions.RequestException, requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            print("Error connecting to DS Portal API: {}".format(e))
            sys.exit(1)
    else:
        print("invalid URL {}".format(api_url))
        return None
    
    if response.status_code == 200:
        return response.json()
    else:
        print("HTTP response code: {}".format(response.status_code))
        pprint(response.json())
        return None

def handle_json_csv_output(json_data, json_, csv_, output_file, raw):
    if csv_:
        flattened_json = json_normalize(json_data)
        if output_file:
            flattened_json.to_csv(output_file, mode='a+')
        else:
            print(flattened_json.to_csv())
    elif json_:
        handle_json_output(json_data, raw)

