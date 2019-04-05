#!/usr/bin/env python3
import json
import pandas
import sys
import requests
import click
import time
import os

from . import sl_constants
from . import sl_helpers
from pathlib import Path
from dotmap import DotMap
from netaddr import IPAddress
from pandas.io.json import json_normalize
from blessed import Terminal
from retrying import retry

__author__ = "Richard Gold"
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
PROFILE_FILE = os.path.join(str(Path.home()), '.shadowline', 'profile')

blessed_t = Terminal()
settings = DotMap()

@click.group(context_settings=CONTEXT_SETTINGS)
@click.option('--profile', default='DEFAULT', help="Name of profile to use. 'DEFAULT' if not specified.")
@click.pass_context
def main(ctx, profile):
    """
    ShadowLine: A command-line API for Digital Shadows SearchLight
    """
    if ctx.invoked_subcommand == 'setup_profile':
        # create_profile method can be called without existing credentials
        pass
    else:
        #print("Running with profile: {}".format(profile))
        if os.path.exists(PROFILE_FILE):
            import configparser
            config = configparser.ConfigParser()
            config.read(PROFILE_FILE)
            if ((profile == 'DEFAULT' or profile in config.sections())
                    and 'username' in config[profile] and 'password' in config[profile]):
                settings.USERNAME = config[profile]['username']
                settings.PASSWORD = config[profile]['password']
            else:
                raise click.UsageError("Attempted to use profile {} for profile file {} but no credentials found".format(profile, PROFILE_FILE))
        else:
            raise click.UsageError('No credentials provided either as command-line arguments or in a profile file.')

def retry_if_requests_error(exception):
    return isinstance(exception, requests.exceptions.ConnectionError)


@retry(wait_exponential_multiplier=1000, wait_exponential_max=100000, retry_on_exception=retry_if_requests_error)
def api_call(endpoint,cmd, api_filter=None):
    s = requests.Session()
    s.auth = (settings.USERNAME, settings.PASSWORD)
    
    response = ""
    
    try:
        if cmd == 'get':
            if api_filter:
                response = s.get("{}{}".format(sl_constants.API_URL, endpoint), headers=sl_constants.HEADERS, json=api_filter)
            else:
                response = s.get("{}{}".format(sl_constants.API_URL, endpoint), headers=sl_constants.HEADERS)
        elif cmd == 'post':
            if api_filter:
                response = s.post("{}{}".format(sl_constants.API_URL, endpoint), headers=sl_constants.HEADERS, json=api_filter)                
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        print("Error connecting to DS Portal API: {}".format(e))
        sys.exit(1)

    if response.status_code == 200:
        return response.json()
    else:
        print(response.status_code)
        print(response.text)
        return None

def common_options(function):
    function = click.option('--json', '-j', 'json_', help='Print colorized JSON output from the API', default=False, is_flag=True)(function)
    function = click.option('--raw', '-r', help='Print the raw JSON output', default=False, is_flag=True)(function)
    function = click.option('--csv', '-c', 'csv_', help='Print CSV output from the API', default=False, is_flag=True)(function)
    function = click.option('--output_file', '-o', help='Output file of results from indicator lookups', type=str)(function)

    return function

@main.command('setup_profile', short_help='Setup a profile to store API credentials')
@click.option('--profile', prompt=True)
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True,
              confirmation_prompt=True)
def setup_profile(profile, username, password):
    try:
        os.makedirs(os.path.join(str(Path.home()), '.shadowline'))
    except FileExistsError:
        # directory already exists
        pass
    Path(PROFILE_FILE).touch(mode=0o600, exist_ok=True)
    import configparser
    config = configparser.ConfigParser()
    config.read(PROFILE_FILE)
    if profile == 'DEFAULT':
        # don't need to setup DEFAULT
        # but it doesn't appear in sections()
        # so explicitly skip
        pass
    elif profile not in config.sections():
        config[profile] = {}
    config[profile]['username'] = username
    config[profile]['password'] = password
    with open(PROFILE_FILE, 'w') as f:
        config.write(f)

@main.command('databreach_summary', short_help='Retrieve a summary of databreaches')
@common_options
def databreach_summary(csv_, output_file, json_, raw):
    
    json_data = api_call("{}".format(sl_constants.DATABREACH_SUMMARY_CMD), 'get')
    
    if json_data:
        if csv_:
            csv_df = pandas.read_json(json.dumps(json_data))
            if output_file:
                csv_df.to_csv(output_file, mode='a+')
            else:
                print(csv_df.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            print("{} {}".format(blessed_t.blue("Total Breaches:"), blessed_t.white("{}".format(json_data['totalBreaches']))))
            for breach in json_data['breachesPerDomain']:
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("{} breaches for domain {}".format(breach['count'], breach['key'])))
            print("{} {}".format(blessed_t.blue("Total Usernames:"), blessed_t.white("{}".format(json_data['totalUsernames']))))
            for usernames in json_data['usernamesPerDomain']:
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("{} usernames for domain {}".format(usernames['count'], usernames['key'])))
    else:
        click.echo("An API call error occurred")

@main.command('databreach_list', short_help='Lists the details of a specific breach')
@click.option('--breach_id', help='Provide a breach ID to list the details of a specific breach', type=int)
@common_options
def databreach_list(breach_id, csv_, output_file, json_, raw):
    
    if breach_id:
        json_data = api_call("{}{}".format(sl_constants.DATABREACH_FIND_ID_CMD, breach_id), 'get', api_filter=sl_constants.DATABREACH_FILTER)
    else:
        json_data = api_call("{}".format(sl_constants.DATABREACH_FIND_CMD), 'post', api_filter=sl_constants.DATABREACH_FILTER)
        
    if json_data:
        if csv_:
            flattened_json = json_normalize(json_data)
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            if "content" in json_data:
                print(blessed_t.blue("Total Breaches"), blessed_t.white("{}".format(len(json_data['content']))))
                for breach in json_data['content']:
                    print(blessed_t.blue("Title"), blessed_t.white("{}".format(breach['title'])))
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("number of usernames impacted for organization"), blessed_t.cyan("{}".format(breach['organisationUsernameCount'])))
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("breach published on"), blessed_t.cyan("{}".format(breach['published'])))
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("severity"), blessed_t.cyan("{}".format(breach['incident']['severity'])))
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("breach ID"), blessed_t.cyan("{}".format(breach['id'])))
            else:
                print(blessed_t.blue("Title"), blessed_t.white("{}".format(json_data['title'])))
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("breach occurred on"), blessed_t.cyan("{}".format(json_data['occurred'])))
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("severity"), blessed_t.cyan("{}".format(json_data['incident']['severity'])))
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("breach ID"), blessed_t.cyan("{}".format(json_data['id'])))
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("data classes in breach"))
                for data_class in json_data['dataClasses']:
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("data classes in breach"), blessed_t.cyan("{}".format(data_class)))
    else:
        click.echo("An API call error occurred")
        
@main.command('databreach_username', short_help='Lists usernames impacted by a specific breach')
@click.option('--breach_id', help='Provide a breach ID to list the details of a specific breach', type=int, required=True)
@common_options
def databreach_usernames(breach_id, csv_, output_file, json_, raw):

    json_data = api_call("{}".format(sl_constants.DATABREACH_FIND_USERNAMES_CMD), 'post', api_filter=sl_constants.DATABREACH_FILTER)
    
    if json_data:
        if csv_:
            csv_df = pandas.read_json(json.dumps(json_data['content']))
            if output_file:
                csv_df.to_csv(output_file, mode='a+')
            else:
                print(csv_df.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            print(blessed_t.blue("Total Usernames"), blessed_t.white("{}".format(len(json_data['content']))))
            for row in json_data['content']:
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("username"), blessed_t.cyan("{}".format(row['username'])), blessed_t.yellow("breach count"), blessed_t.cyan("{}".format(row['breachCount'])))
    else:
        click.echo("An API call error occurred")
        
@main.command('domain_lookup', short_help='Perform a DNS lookup for a domain')
@common_options
@click.argument('domain')
def domain_lookup(domain, csv_, output_file, json_, raw):

    json_data = api_call("{}{}".format(sl_constants.DOMAIN_LOOKUP_CMD, domain), 'get')
    
    if json_data:
        if csv_:
            csv_df = pandas.read_json(json.dumps(json_data))
            if output_file:
                csv_df.to_csv(output_file, mode='a+')
            else:
                print(csv_df.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            print(blessed_t.blue("Results for domain"), blessed_t.white("{}".format(domain)), blessed_t.blue("from DNS server"), blessed_t.white("{}".format(json_data['dnsServerIpAddress'])))
            for record in json_data['dnsZone']['records']:
                if 'type' in record:
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("type"), blessed_t.cyan("{}".format(record['type'])), blessed_t.yellow("data"), blessed_t.cyan("{}".format(record['data'])))
    else:
        click.echo("An API call error occurred")        

@main.command('domain_whois', short_help='Lookup the domain WHOIS information for a domain')
@common_options
@click.argument('domain')
def domain_whois(domain, csv_, output_file, json_, raw):

    json_data = api_call("{}{}".format(sl_constants.DOMAIN_WHOIS_CMD, domain), 'get')
    
    if json_data:
        if csv_:
            flattened_json = json_normalize(json_data)
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            if 'registrar' in json_data:
                print(blessed_t.blue("Results for domain"), blessed_t.green("{}".format(domain)), blessed_t.blue("registered by"), blessed_t.white("{}".format(json_data['registrar'])))
            else:
                print(blessed_t.blue("Results for domain"), blessed_t.green("{}".format(domain)))

            if 'created' in json_data and 'expires' in json_data and 'updated' in json_data:
                print(blessed_t.blue("Created"), blessed_t.white("{}".format(json_data['created'])), blessed_t.blue("expires"), blessed_t.white("{}".format(json_data['expires'])), blessed_t.blue("updated"), blessed_t.white("{}".format(json_data['updated'])))
            else:
                print("Registration date information missing, suggest using --json to review the raw output")
                
            print(blessed_t.blue("Results for domain"))
            if 'registrant' in json_data:
                if 'email' in json_data['registrant'] and 'name' in json_data['registrant'] and 'organization' in json_data['registrant'] and 'telephone' in json_data['registrant']:
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("email"), blessed_t.cyan("{}".format(json_data['registrant']['email'])), blessed_t.yellow("name"), blessed_t.cyan("{}".format(json_data['registrant']['name'])), blessed_t.yellow("organization"), blessed_t.cyan("{}".format(json_data['registrant']['organization'])), blessed_t.yellow("telephone"), blessed_t.cyan("{}".format(json_data['registrant']['telephone'])))
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("street"), blessed_t.cyan("{}".format(json_data['registrant']['address']['street1'])), blessed_t.yellow("city"), blessed_t.cyan("{}".format(json_data['registrant']['address']['city'])), blessed_t.yellow("state"), blessed_t.cyan("{}".format(json_data['registrant']['address']['state'])), blessed_t.yellow("country"), blessed_t.cyan("{}".format(json_data['registrant']['address']['country'])))
                else:
                    print("Registrant data missing, suggest using --json to review the raw output")
    else:
        click.echo("An API call error occurred")                
        
def ip_whois_search(ip_addr):
    ip_whois_filter = sl_constants.IP_WHOIS_FILTER
    ip_whois_filter['query'] = ip_addr
    
    json_data = api_call(sl_constants.SEARCH_CMD, 'post', api_filter=ip_whois_filter)
    
    if json_data:
        ip_uuid = json_data['content'][0]['entity']['id']
        return ip_uuid
    else:
        click.echo("An API call error occurred")        

    return False

@main.command('ipaddr_whois', short_help='Lookup the WHOIS information for an IP address')
@common_options
@click.argument('ip_addr')
def ipaddr_whois(ip_addr, csv_, output_file, json_, raw):

    if sl_helpers.is_ipaddr(ip_addr):
        ip_uuid = ip_whois_search(ip_addr)

        json_data = api_call("{}{}".format(sl_constants.IPADDR_WHOIS_CMD, ip_uuid), 'get')
        
        if json_data:
            if csv_:
                flattened_json = json_normalize(json_data)
                if output_file:
                    flattened_json.to_csv(output_file, mode='a+')
                else:
                    print(flattened_json.to_csv())
            elif json_:
                sl_helpers.handle_json_output(json_data, raw)
            else:
                print(blessed_t.blue("IP address"), blessed_t.green("{}".format(ip_addr)))
                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("NetName"), blessed_t.cyan(json_data['netName']), blessed_t.yellow("Country"), blessed_t.cyan(json_data['countryName']), blessed_t.yellow("IP range start"), blessed_t.cyan(json_data['ipRangeStart']), blessed_t.yellow("IP range end"), blessed_t.cyan(json_data['ipRangeEnd']))
        else:
            click.echo("An API call error occurred")                
    else:
        print("Invalid IP address provided: {}".format(ip_addr))


@main.command('cve_search', short_help='Lookup a CVE')
@common_options
@click.argument('cve')
def cve_search(cve, csv_, output_file, json_, raw):

    cve_filter = sl_constants.CVE_FILTER
    cve_filter['query'] = cve
    
    json_data = api_call(sl_constants.SEARCH_CMD, 'post', api_filter=cve_filter)

    if json_data:
        if csv_:
            flattened_json = json_normalize(json_data['content'])
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            print(blessed_t.blue("Results"), blessed_t.green("{}".format(cve)))
            for cve_entry in json_data['content']:
                if cve_entry['type'] == "VULNERABILITY":
                    print(blessed_t.blue("Description"), blessed_t.white(cve_entry['entity']['description']))
                    if len(cve_entry['entity']['cvss2Score'])>1:
                        print(blessed_t.blue("CVSS2 score"))
                        print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("Access Complexity"), blessed_t.cyan("{}".format(cve_entry['entity']['cvss2Score']['accessComplexity'])), blessed_t.yellow("Authentication"), blessed_t.cyan("{}".format(cve_entry['entity']['cvss2Score']['authentication'])), blessed_t.yellow("Availability Impact"), blessed_t.cyan("{}".format(cve_entry['entity']['cvss2Score']['availabilityImpact'])), blessed_t.yellow("Base Score"), blessed_t.cyan("{}".format(cve_entry['entity']['cvss2Score']['baseScore'])), blessed_t.yellow("Confidentiality Impact"), blessed_t.cyan("{}".format(cve_entry['entity']['cvss2Score']['confidentialityImpact'])), blessed_t.yellow("Integrity Impact"), blessed_t.cyan("{}".format(cve_entry['entity']['cvss2Score']['integrityImpact'])))
                    print(blessed_t.blue("Affected CPE summary"))
                    cpe_list = []
                    for entry in cve_entry['entity']['relatedCPEs']:
                        cpe = "{}:{}".format(entry.split(":")[2], entry.split(":")[3])
                        if cpe not in cpe_list:
                            cpe_lisblessed_t.append(cpe)
                
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("CPEs"), blessed_t.cyan(",".join(cpe_list)))
                    print("")
            print("")
            exploits = 0
            for entry in json_data['facets']['typeCounts']:
                if entry['key'] == 'EXPLOIT':
                    exploits = entry['count']
            print(blessed_t.blue("Available exploits"), blessed_t.white(str(exploits)))
            for entry in json_data['content']:
                if entry['type'] == "EXPLOIT":
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("Title"), blessed_t.cyan(entry['entity']['title']),blessed_t.yellow("Platform"), blessed_t.cyan(entry['entity']['platform']),blessed_t.yellow("Source"), blessed_t.cyan(entry['entity']['source']),blessed_t.yellow("Type"), blessed_t.cyan(entry['entity']['type']))
                    print(blessed_t.move_right, blessed_t.move_right, blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("URL"), blessed_t.white(entry['entity']['sourceUri']))
    else:
        click.echo("An API call error occurred")                

# TODO add CSV
@main.command('threats', short_help='Look up a threat record')
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@click.option('--json', '-j', 'json_', help='Print colorized JSON output from the API', default=False, is_flag=True)
@click.option('--raw', '-r', help='Print the raw JSON output', default=False, is_flag=True)
@click.argument('incident_id')
def threats(incident_id, iocs, json_, raw):    
    if incident_id:
        if iocs:
            json_data = api_call("{}{}/iocs".format(sl_constants.INTELTHREATS_CMD, incident_id), 'post', api_filter=sl_constants.IOCS_FILTER)
            if json_data:
                if json_:
                    sl_helpers.handle_json_output(json_data, raw)
                else:
                    for ioc in json_data['content']:
                        print("type {} value {}".format(ioc['type'], ioc['value']))
            else:
                click.echo("An API call error occurred")                
        else:
            json_data = api_call("{}{}".format(sl_constants.INTELTHREATS_CMD, incident_id), 'get', api_filter=sl_constants.THREAT_FILTER)
            
            if json_data:
                if json_:
                    sl_helpers.handle_json_output(json_data, raw)
            else:
                click.echo("An API call error occurred")                
    else:
        json_data = api_call("{}{}".format(sl_constants.INTELTHREATS_CMD, sl_constants.INTELTHREATS_FIND_CMD), 'post', api_filter=sl_constants.THREAT_FILTER)
        if json_data:
            if json_:
                sl_helpers.handle_json_output(json_data, raw)
            else:
                print(blessed_t.blue("Incident summary"))
                for entry in json_data['content']:
                    print('id: {}'.format(entry['id']))
        else:
            click.echo("An API call error occurred")
            
@main.command('incidents', short_help='Retrieve all incidents or an incident')
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@common_options
def incidents(incident_id, iocs, csv_, output_file, json_, raw):
    json_data = ""
    if incident_id:
        json_data = api_call("{}{}".format(sl_constants.INCIDENTS_CMD, incident_id), 'get')
    else:
        json_data = api_call("{}{}".format(sl_constants.INCIDENTS_CMD, sl_constants.INCIDENTS_FIND_CMD), 'get')
        
    if json_data:
        if csv_:
            flattened_json = json_normalize(json_data['content'])
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            print(blessed_t.blue("Incident summary"))
            if incident_id:
                print('Scope: {} Type: {} Sub-type: {} Severity: {} Title: {}'.format(json_data['scope'], json_data['type'], json_data['subType'], json_data['severity'], json_data['title']))
            else:
                for entry in json_data['content']:
                    print('id: {}'.format(entry['id']))
    else:
        click.echo("An API call error occurred")

@main.command('intelligence', short_help='search through the Digital Shadows repository')
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@click.option('--output_file', '-o', help='Output file of results from indicator lookups', type=str)
@common_options
def intelligence(csv_, input_file, output_file, json_, raw, iocs, incident_id):
    search_filter = {"filter":{"severities":[],"tags":[],"tagOperator":"AND","dateRange":"ALL","dateRangeField":"published","types":[],"withFeedback":"true","withoutFeedback":"true"},"sort":{"property":"date","direction":"DESCENDING"},"pagination":{"size":50,"offset":0}}

    if incident_id:
        if iocs:
            json_data = api_call("{}{}/iocs".format(sl_constants.INTELINCIDENTS_CMD, incident_id), 'post', api_filter=sl_constants.IOCS_FILTER)
            
            if json_data:
                if json_:
                    sl_helpers.handle_json_output(json_data, raw)
                else:
                    for ioc in json_data['content']:
                        print("type {} value {}".format(ioc['type'], ioc['value']))
            else:
                click.echo("An API call error occurred")
        else:
            json_data = api_call("{}{}".format(sl_constants.INTELINCIDENTS_CMD, incident_id), 'get', api_filter=sl_constants.THREAT_FILTER)
            
            if json_data:
                if json_:
                    sl_helpers.handle_json_output(json_data, raw)
            else:
                click.echo("An API call error occurred")
    else:
        json_data = api_call("{}{}".format(sl_constants.INTELINCIDENTS_CMD, sl_constants.INTELINCIDENTS_FIND_CMD), 'post',  api_filter=search_filter)
        if json_data:
            if json_:
                sl_helpers.handle_json_output(json_data, raw)
        else:
            click.echo("An API call error occurred")
        
@main.command('indicator', short_help='search for an IP address as an Indicator Of Compromise')
@click.option('--ipaddr', help='Provide an IP address to query', type=str)
@click.option('--input_file', '-i', help='Input file of IP addresses to look up', type=click.File('r'))
@common_options
def indicator(ipaddr, csv_, input_file, output_file, json_, raw):
    search_cmd = "search/find"

    if input_file:
        for line in input_file:
            ipaddr = IPAddress(line.split(':')[0])
            if sl_helpers.is_ipaddr(ipaddr):
                search_filter = {"filter":{"dateRange":"ALL","tags":[],"types":["INDICATOR_FEED"]},"pagination":{"offset":0,"size":25},"sort":{"property":"relevance","direction":"DESCENDING"},"query":str(ipaddr),"facets":["RESULTS_TYPE"]}
                json_data = api_call(search_cmd, 'post', api_filter=search_filter)
                if json_data:
                    if csv_:
                        flattened_json = json_normalize(json_data['content'])
                        if output_file:
                            flattened_json.to_csv(output_file, mode='a+')
                        else:
                            print(flattened_json.to_csv())
                    elif json_:
                        sl_helpers.handle_json_output(json_data, raw)
                    else:
                        for entry in json_data['content']:
                            if entry['type'] == 'WEBROOT_IP':
                                print("{},{}".format(ipaddr, entry['entity']['currentlyClassifiedAsThreat']))
                else:
                    click.echo("An API call error occurred")
                    sys.exit(1)
            time.sleep(60)
    elif ipaddr:
        if sl_helpers.is_ipaddr(ipaddr):
            search_filter = {"filter":{"dateRange":"ALL","tags":[],"types":["INDICATOR_FEED"]},"pagination":{"offset":0,"size":25},"sort":{"property":"relevance","direction":"DESCENDING"},"query":str(ipaddr),"facets":["RESULTS_TYPE"]}
            json_data = api_call(search_cmd, 'post', api_filter=search_filter)
            if json_data:
                if csv_:
                    flattened_json = json_normalize(json_data['content'])
                    if output_file:
                        flattened_json.to_csv(output_file, mode='a+')
                    else:
                        print(flattened_json.to_csv())
                elif json_:
                    sl_helpers.handle_json_output(json_data, raw)
                else:
                    for entry in json_data['content']:
                        if entry['type'] == 'WEBROOT_IP':
                            print(blessed_t.blue("IP address:"), blessed_t.white("{}".format(ipaddr)), blessed_t.blue("Classified as threat:"), blessed_t.white("{}".format(entry['entity']['currentlyClassifiedAsThreat'])), blessed_t.blue("Reputation score:"),  blessed_t.white("{}".format(entry['entity']['reputationScore'])), blessed_t.blue("Timestamp:"), blessed_t.white("{}".format(entry['entity']['updatedDateTime'])))
                            for ip_history in entry['entity']['ipThreatHistory']:
                                print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("Historical classification:"), blessed_t.cyan("{}".format(ip_history['classifiedAsThreat'])), blessed_t.yellow("Historical timestamp"), blessed_t.cyan("{}".format(ip_history['timestamp'])))
            else:
                click.echo("An API call error occurred")
                sys.exit(1)
        
if __name__ == "__main__":
    main()
