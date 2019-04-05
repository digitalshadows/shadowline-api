#!/usr/bin/env python3
import json
import pandas
import sys
import click
import time
import os

from . import sl_constants
from . import sl_helpers
from . import sl_console
from pathlib import Path
from dotmap import DotMap
from netaddr import IPAddress
from pandas.io.json import json_normalize

__author__ = "Richard Gold"
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
PROFILE_FILE = os.path.join(str(Path.home()), '.shadowline', 'profile')

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
    
    json_data = sl_helpers.api_call("{}".format(sl_constants.DATABREACH_SUMMARY_CMD), 'get', settings)
    
    if json_data:
        if csv_:
            csv_df = pandas.read_json(json.dumps(json_data))
            if output_file:
                csv_df.to_csv(output_file)
            else:
                print(csv_df.to_csv())
        elif json_:
            sl_helpers.handle_json_output(json_data, raw)
        else:
            sl_console.echo_databreach_summary(json_data)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)
        
@main.command('databreach_list', short_help='Lists the details of a specific breach')
@click.option('--breach_id', help='Provide a breach ID to list the details of a specific breach', type=int)
@common_options
def databreach_list(breach_id, csv_, output_file, json_, raw):
    
    if breach_id:
        json_data = sl_helpers.api_call("{}{}".format(sl_constants.DATABREACH_FIND_ID_CMD, breach_id), 'get', settings, api_filter=sl_constants.DATABREACH_FILTER)
    else:
        json_data = sl_helpers.api_call("{}".format(sl_constants.DATABREACH_FIND_CMD), 'post', settings, api_filter=sl_constants.DATABREACH_FILTER)
        
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
            sl_console.echo_databreach_list(json_data)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)
        
@main.command('databreach_usernames', short_help='Lists usernames impacted by a specific breach')
@common_options
def databreach_usernames(csv_, output_file, json_, raw):

    json_data = sl_helpers.api_call("{}".format(sl_constants.DATABREACH_FIND_USERNAMES_CMD), 'post', settings, api_filter=sl_constants.DATABREACH_FILTER)
    
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
            sl_console.echo_databreach_usernames(json_data)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)
        
@main.command('domain_lookup', short_help='Perform a DNS lookup for a domain')
@common_options
@click.argument('domain')
def domain_lookup(domain, csv_, output_file, json_, raw):

    json_data = sl_helpers.api_call("{}{}".format(sl_constants.DOMAIN_LOOKUP_CMD, domain), 'get', settings)
    
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
            sl_console.echo_domain_lookup(json_data)
    else:
        click.echo("An API call error occurred")        
        sys.exit(1)
        
@main.command('domain_whois', short_help='Lookup the domain WHOIS information for a domain')
@common_options
@click.argument('domain')
def domain_whois(domain, csv_, output_file, json_, raw):

    json_data = sl_helpers.api_call("{}{}".format(sl_constants.DOMAIN_WHOIS_CMD, domain), 'get', settings)
    
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
            sl_console.echo_domain_whois(json_data)
    else:
        click.echo("An API call error occurred")                
        sys.exit(1)
        
def ip_whois_search(ip_addr):
    ip_whois_filter = sl_constants.IP_WHOIS_FILTER
    ip_whois_filter['query'] = ip_addr
    
    json_data = sl_helpers.api_call(sl_constants.SEARCH_CMD, 'post', settings, api_filter=ip_whois_filter)
    
    if json_data:
        ip_uuid = json_data['content'][0]['entity']['id']
        return ip_uuid
    else:
        click.echo("An API call error occurred")        
        sys.exit(1)
    return False

@main.command('ipaddr_whois', short_help='Lookup the WHOIS information for an IP address')
@common_options
@click.argument('ip_addr')
def ipaddr_whois(ip_addr, csv_, output_file, json_, raw):

    if sl_helpers.is_ipaddr(ip_addr):
        ip_uuid = ip_whois_search(ip_addr)

        json_data = sl_helpers.api_call("{}{}".format(sl_constants.IPADDR_WHOIS_CMD, ip_uuid), 'get', settings)
        
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
                sl_console.echo_ipaddr_whois(json_data, ip_addr)
        else:
            click.echo("An API call error occurred")
            sys.exit(1)
    else:
        print("Invalid IP address provided: {}".format(ip_addr))


@main.command('cve_search', short_help='Lookup a CVE')
@common_options
@click.argument('cve')
def cve_search(cve, csv_, output_file, json_, raw):

    cve_filter = sl_constants.CVE_FILTER
    cve_filter['query'] = cve
    
    json_data = sl_helpers.api_call(sl_constants.SEARCH_CMD, 'post', settings, api_filter=cve_filter)

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
            sl_console.echo_cve_search(json_data, cve)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)

@main.command('threats', short_help='Look up a threat record')
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@common_options
def threats(incident_id, iocs, json_, raw, csv_, output_file):    
    if incident_id:
        if iocs:
            json_data = sl_helpers.api_call("{}{}/iocs".format(sl_constants.INTELTHREATS_CMD, incident_id), 'post', settings, api_filter=sl_constants.IOCS_FILTER)
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
                    sl_console.echo_threats_iocs(json_data)
            else:
                click.echo("An API call error occurred")
                sys.exit(1)
        else:
            json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELTHREATS_CMD, incident_id), 'get', settings, api_filter=sl_constants.THREAT_FILTER)
            
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
                    sl_console.echo_threats_summary(json_data)
            else:
                click.echo("An API call error occurred")
                sys.exit(1)
    else:
        json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELTHREATS_CMD, sl_constants.INTELTHREATS_FIND_CMD), 'post', settings, api_filter=sl_constants.THREAT_FILTER)
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
                sl_console.echo_threats(json_data)
        else:
            click.echo("An API call error occurred")
            sys.exit(1)
            
@main.command('incidents', short_help='Retrieve all incidents or an incident')
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@common_options
def incidents(incident_id, iocs, csv_, output_file, json_, raw):
    json_data = ""
    if incident_id:
        json_data = sl_helpers.api_call("{}{}".format(sl_constants.INCIDENTS_CMD, incident_id), 'get', settings)
    else:
        json_data = sl_helpers.api_call("{}{}".format(sl_constants.INCIDENTS_CMD, sl_constants.INCIDENTS_FIND_CMD), 'get', settings)
        
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
        sys.exit(1)

@main.command('intelligence', short_help='search through the Digital Shadows repository')
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@common_options
def intelligence(csv_, input_file, output_file, json_, raw, iocs, incident_id):
    if incident_id:
        if iocs:
            json_data = sl_helpers.api_call("{}{}/iocs".format(sl_constants.INTELINCIDENTS_CMD, incident_id), 'post', settings, api_filter=sl_constants.IOCS_FILTER)
            
            if json_data:
                if json_:
                    sl_helpers.handle_json_output(json_data, raw)
                else:
                    for ioc in json_data['content']:
                        print("type {} value {}".format(ioc['type'], ioc['value']))
            else:
                click.echo("An API call error occurred")
                sys.exit(1)
        else:
            json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELINCIDENTS_CMD, incident_id), 'get', settings, api_filter=sl_constants.THREAT_FILTER)
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
                click.echo("An API call error occurred")
                sys.exit(1)
    else:
        json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELINCIDENTS_CMD, sl_constants.INTELINCIDENTS_FIND_CMD), 'post', settings, api_filter=sl_constants.INTEL_FILTER)
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
            click.echo("An API call error occurred")
            sys.exit(1)
        
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
                json_data = sl_helpers.api_call(search_cmd, 'post', settings, api_filter=search_filter)
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
            json_data = sl_helpers.api_call(search_cmd, 'post', settings, api_filter=search_filter)
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
