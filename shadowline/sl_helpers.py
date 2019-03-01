import json

from netaddr import IPAddress, IPNetwork
from pygments import highlight, lexers, formatters


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

