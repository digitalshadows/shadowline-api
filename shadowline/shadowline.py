#!/usr/bin/env python3
import json
import pandas
import sys
import click
import time
import os

import searchlight
import sl_helpers
import sl_console

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
    api = searchlight.searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
    
    response = api.get_databreach_summary()

    if response:
        if csv_:
            csv_df = pandas.read_json(json.dumps(response))
            if output_file:
                csv_df.to_csv(output_file)
            else:
                print(csv_df.to_csv())
        elif json_:
            sl_helpers.handle_json_output(response, raw)
        else:
            sl_console.echo_databreach_summary(response)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)


@main.command('databreach_list', short_help='Lists the details of a specific breach')
@click.option('--breach_id', help='Provide a breach ID to list the details of a specific breach', type=int)
@common_options
def databreach_list(breach_id, csv_, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
    response = ""
    
    if breach_id:
        response = api.get_databreach_list(breach_id)
    else:
        response = api.get_databreach_list(None)
        
    if response:       
        if csv_:
            flattened_json = json_normalize(response)
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(response, raw)
        else:
            sl_console.echo_databreach_list(response)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)

@main.command('databreach_usernames', short_help='Lists usernames impacted by a specific breach')
@common_options
def databreach_usernames(csv_, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)

    response = api.get_databreach_usernames()
    
    if response:
        if csv_:
            csv_df = pandas.read_json(json.dumps(response['content']))
            if output_file:
                csv_df.to_csv(output_file, mode='a+')
            else:
                print(csv_df.to_csv())
        elif json_:
            sl_helpers.handle_json_output(response, raw)
        else:
            sl_console.echo_databreach_usernames(response)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)

@main.command('domain_lookup', short_help='Perform a DNS lookup for a domain')
@common_options
@click.argument('domain')
def domain_lookup(domain, csv_, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
    
    response = api.get_domain(domain)
    
    if response:
        if csv_:
            csv_df = pandas.read_json(json.dumps(response))
            if output_file:
                csv_df.to_csv(output_file, mode='a+')
            else:
                print(csv_df.to_csv())
        elif json_:
            sl_helpers.handle_json_output(response, raw)
        else:
            sl_console.echo_domain_lookup(response)
    else:
        click.echo("An API call error occurred")        
        sys.exit(1)
        

@main.command('domain_whois', short_help='Lookup the domain WHOIS information for a domain')
@common_options
@click.argument('domain')
def domain_whois(domain, csv_, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
    
    response = api.get_domain_whois(domain)
    
    if response:
        if csv_:
            flattened_json = json_normalize(response)
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(response, raw)
        else:
            sl_console.echo_domain_whois(response)
    else:
        click.echo("An API call error occurred")                
        sys.exit(1)

@main.command('ipaddr_whois', short_help='Lookup the WHOIS information for an IP address')
@common_options
@click.argument('ipaddr')
def ipaddr_whois(ipaddr, csv_, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
    
    if sl_helpers.is_ipaddr(ipaddr):
        response = api.get_ipaddr_whois(ipaddr)
        if response:
            if csv_:
                flattened_json = json_normalize(response)
                if output_file:
                    flattened_json.to_csv(output_file, mode='a+')
                else:
                    print(flattened_json.to_csv())
            elif json_:
                sl_helpers.handle_json_output(response, raw)
            else:
                sl_console.echo_ipaddr_whois(response, ipaddr)
        else:
            click.echo("An API call error occurred")
            sys.exit(1)
    else:
        print("Invalid IP address provided: {}".format(ipaddr))

@main.command('cve_search', short_help='Lookup a CVE')
@common_options
@click.argument('cve')
def cve_search(cve, csv_, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
    
    response = api.get_cve(cve)
    
    if response:
        if csv_:
            flattened_json = json_normalize(response['content'])
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(response, raw)
        else:
            sl_console.echo_cve_search(response, cve)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)


@main.command('threats', short_help='Look up a threat record')
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@common_options
def threats(incident_id, iocs, json_, raw, csv_, output_file):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)

    if incident_id:
        if iocs:
            response = api.get_threats(incident_id, iocs)
        else:
            response = api.get_threats(incident_id, None)
    else:
        response = api.get_threats(None, None)
        
    if response:
        if json_:
            sl_helpers.handle_json_output(response, raw)
        elif csv_:
            flattened_json = json_normalize(response['content'])
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        else:
            if iocs:
                sl_console.echo_threats_iocs(response)
            elif incident_id:
                sl_console.echo_threats(response)
            else:
                sl_console.echo_threats_summary(response)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)

@main.command('incidents', short_help='Retrieve all incidents or an incident')
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@common_options
def incidents(incident_id, csv_, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
        
    response = ""
    if incident_id:
        response = api.get_incidents(incident_id)
    else:
        response = api.get_incidents(None)
        
    if response:
        if csv_:
            flattened_json = json_normalize(response['content'])
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        elif json_:
            sl_helpers.handle_json_output(response, raw)
        else:
            sl_console.echo_incidents(response, incident_id)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)


def lookup_cve(cve):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)

    priority_result = {}
    cve_result = []
    exploit_result = []
    actor_result = []
    event_result = []
    campaign_result = []
    intel_incident_result = []
    facet_result = []
    
    cve_response = api.get_cve_priority(cve)
    #sl_helpers.handle_json_output(cve_response, raw)
    profiles_response = api.get_profiles(cve)
    #sl_helpers.handle_json_output(profiles_response, raw)
    intel_incident_response = api.get_intel_incident(cve)
    #sl_helpers.handle_json_output(intel_incident_response, raw)
    
    for result in cve_response['content']:
        if result['type'] == 'VULNERABILITY':
            cve_id = result['entity']['cveIdentifier']
            if cve_id == cve:
                description = result['entity']['description']
                cvss2score = result['entity']['cvss2Score']['baseScore']
                authentication = result['entity']['cvss2Score']['authentication']
                access_vector = result['entity']['cvss2Score']['accessVector']
                access_complexity = result['entity']['cvss2Score']['accessComplexity']
                cve_result.append({'cve_id':cve_id, 'description':description, 'cvss2score':cvss2score, 'authentication':authentication, 'access_vector':access_vector, 'access_complexity':access_complexity})
        elif result['type'] == 'EXPLOIT':
            exploit_title = result['entity']['title']
            exploit_type = result['entity']['type']
            exploit_platform = result['entity']['platform']
            exploit_sourceuri = result['entity']['sourceUri']
            exploit_result.append({'exploit_title':exploit_title, 'exploit_type':exploit_type, 'exploit_platform':exploit_platform, 'exploit_sourceuri':exploit_sourceuri})

    for result in profiles_response['content']:
        if result['type'] == 'ACTOR':
            name = result['entity']['primaryTag']['name']
            actor_type = result['entity']['primaryTag']['type']
            threat_level = result['entity']['threatLevel']['type']
            actor_result.append({ 'name':name, 'actor_type':actor_type, 'threat_level':threat_level })
        elif result['type'] == 'EVENT':
            name = result['entity']['primaryTag']['name']
            entity_type = result['entity']['primaryTag']['type']
            event_result.append({ 'name':name, 'entity_type':entity_type })
        elif result['type'] == 'CAMPAIGN':
            name = result['entity']['primaryTag']['name']
            entity_type = result['entity']['primaryTag']['type']
            campaign_result.append({ 'name':name, 'entity_type':entity_type })
    for result in intel_incident_response['content']:
        title = result['entity']['title']
        severity = result['entity']['severity']
        source = result['entity']['entitySummary']['source']
        intel_incident_result.append({ 'title':title, 'severity':severity, 'source':source })

    blog_post = ''
    web_page = ''
    forum_post = ''
    paste = ''
    conversation_fragment = ''
    marketplace_listing = ''
        
    for facets in intel_incident_response['facets']['typeCounts']:
        if facets['key'] == "BLOG_POST":
            blog_post = facets['count']
        elif facets['key'] == "WEB_PAGE":
            web_page = facets['count']
        elif facets['key'] == "FORUM_POST":
            forum_post = facets['count']
        elif facets['key'] == "PASTE":
            paste = facets['count']
        elif facets['key'] == "CONVERSATION_FRAGMENT":
            conversation_fragment = facets['count']
        elif facets['key'] == "MARKETPLACE_LISTING":
            marketplace_listing = facets['count']
        facet_result = { 'blog_post':blog_post, 'web_page':web_page, 'forum_post':forum_post, 'paste':paste, 'conversation_fragment':conversation_fragment, 'marketplace_listing':marketplace_listing }

    priority_result = {'cve_result':cve_result, 'exploit_result':exploit_result, 'actor_result':actor_result, 'event_result':event_result, 'campaign_result':campaign_result, 'intel_incident_result':intel_incident_result, 'facet_result':facet_result}

    return priority_result

def convert_priority_json_to_csv(json_data):
    csv_output = []

    csv_output.append('{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}'.format("CVE","Description","CVSS2","Authentication","AccessVector","AccessComplexity","ExploitTitle","ExploitType","ExploitPlatform","ExploitSourceUri","ACTOR","EVENT","CAMPAIGNS","SHARED_INCIDENT","BlogPost","WebPage","ForumPost","ConversationFragment","MarketplaceListing"))
    
    for exploit in json_data['exploit_result']:
        csv_output.append('{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}'.format(json_data['cve_result'][0]['cve_id'],json_data['cve_result'][0]['description'],json_data['cve_result'][0]['cvss2score'],json_data['cve_result'][0]['authentication'],json_data['cve_result'][0]['access_vector'],json_data['cve_result'][0]['access_complexity'], exploit['exploit_title'], exploit['exploit_type'], exploit['exploit_platform'], exploit['exploit_sourceuri'], len(json_data['actor_result']),len(json_data['event_result']),len(json_data['campaign_result']), len(json_data['intel_incident_result']), json_data['facet_result']['blog_post'], json_data['facet_result']['web_page'], json_data['facet_result']['forum_post'], json_data['facet_result']['paste'], json_data['facet_result']['conversation_fragment'], json_data['facet_result']['marketplace_listing']))
    
    return csv_output

def convert_priority_json_to_csv_all(json_data_list):
    csv_output = []

    csv_output.append('{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}'.format("CVE","Description","CVSS2","Authentication","AccessVector","AccessComplexity","ExploitTitle","ExploitType","ExploitPlatform","ExploitSourceUri","ACTOR","EVENT","CAMPAIGNS","SHARED_INCIDENT","BlogPost","WebPage","ForumPost","ConversationFragment","MarketplaceListing"))

    for json_data in json_data_list:
        for exploit in json_data['exploit_result']:
            csv_output.append('{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}'.format(json_data['cve_result'][0]['cve_id'],json_data['cve_result'][0]['description'],json_data['cve_result'][0]['cvss2score'],json_data['cve_result'][0]['authentication'],json_data['cve_result'][0]['access_vector'],json_data['cve_result'][0]['access_complexity'], exploit['exploit_title'], exploit['exploit_type'], exploit['exploit_platform'], exploit['exploit_sourceuri'], len(json_data['actor_result']),len(json_data['event_result']),len(json_data['campaign_result']), len(json_data['intel_incident_result']), json_data['facet_result']['blog_post'], json_data['facet_result']['web_page'], json_data['facet_result']['forum_post'], json_data['facet_result']['paste'], json_data['facet_result']['conversation_fragment'], json_data['facet_result']['marketplace_listing']))
    
    return csv_output


@main.command('priority', short_help='get CVE priorities')
@click.option('--cve', 'cve_', help='Provide a CVE to lookup', type=str)
@click.option('--input_file', '-i', help='Input file of CVEs to look up', type=click.File('r'))
@common_options
def priority(cve_, csv_, input_file, output_file, json_, raw):
    response = {}
    all_response = []
    
    if input_file:
        for cve in input_file:
            response = lookup_cve(cve.rstrip())
            if response:
                all_response.append(response)
        if csv_:
            csv_output = convert_priority_json_to_csv_all(all_response)
            if output_file:
                with open(output_file, 'a+') as f:
                    for line in csv_output:
                        f.write(line+'\n')
            else:
                for line in csv_output:
                    print(line)
        elif json_:
            sl_helpers.handle_json_output(all_response, raw)
        else:
            sl_console.echo_priority(all_response)
    elif cve_:
        response = lookup_cve(cve_)
        if response:
            if csv_:
                flattened_json = convert_priority_json_to_csv(response)
                if output_file:
                    flattened_json.to_csv(output_file, mode='a+')
                else:
                    for line in flattened_json:
                        print(line)
            elif json_:
                sl_helpers.handle_json_output(response, raw)
            else:
                sl_console.echo_priority(response)
        else:
            click.echo("An API call error occurred")
            sys.exit(1)
            
@main.command('intelligence', short_help='search through the Digital Shadows repository')
@click.option('--incident_id', help='Provide an incident ID to lookup', type=str)
@click.option('--input_file', '-i', help='Input file of IP addresses to look up', type=click.File('r'))
@click.option('--iocs', help='Retrieve the IOCs for a threat record', default=False, is_flag=True)
@common_options
def intelligence(csv_, input_file, output_file, json_, raw, iocs, incident_id):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)
    
    if incident_id:
        if iocs:
            response = api.get_intel(incident_id, iocs)
        else:
            response = api.get_intel(incident_id, None)
    else:
        response = api.get_intel(None, None)
        
    if response:
        if json_:
            sl_helpers.handle_json_output(response, raw)
        elif csv_:
            flattened_json = json_normalize(response['content'])
            if output_file:
                flattened_json.to_csv(output_file, mode='a+')
            else:
                print(flattened_json.to_csv())
        else:
            if iocs:
                sl_console.echo_intelligence_iocs(response)
            elif incident_id:
                sl_console.echo_intelligence(response)
            else:
                sl_console.echo_intelligence_summary(response)
    else:
        click.echo("An API call error occurred")
        sys.exit(1)

@main.command('indicator', short_help='search for an IP address as an Indicator Of Compromise')
@click.option('--ipaddr', help='Provide an IP address to query', type=str)
@click.option('--input_file', '-i', help='Input file of IP addresses to look up', type=click.File('r'))
@common_options
def indicator(ipaddr, csv_, input_file, output_file, json_, raw):
    api = searchlight.SearchLightApi(settings.USERNAME, settings.PASSWORD)

    if input_file:
        for line in input_file:
            ipaddr = IPAddress(line.split(':')[0])
            if sl_helpers.is_ipaddr(ipaddr):
                response = api.get_indicators(ipaddr)
                if response:
                    if csv_:
                        flattened_json = json_normalize(response['content'])
                        if output_file:
                            for entry in response['content']:
                                if entry['type'] == 'WEBROOT_IP':
                                    print("{},{}".format(ipaddr, entry['entity']['currentlyClassifiedAsThreat']))
                                    with open(output_file,'a+') as f:
                                        f.write("{},{}\n".format(ipaddr, entry['entity']['currentlyClassifiedAsThreat']))
                            #flattened_json.to_csv(output_file, mode='a+')
                        else:
                            print(flattened_json.to_csv())
                    elif json_:
                        sl_helpers.handle_json_output(response, raw)
                    else:
                        sl_console.echo_indicator(response, ipaddr)
                else:
                    click.echo("An API call error occurred")
                    sys.exit(1)
            time.sleep(60)
    elif ipaddr:
        if sl_helpers.is_ipaddr(ipaddr):
            response = api.get_indicators(ipaddr)
            if response:
                if csv_:
                    flattened_json = json_normalize(response['content'])
                    if output_file:
                        flattened_json.to_csv(output_file, mode='a+')
                    else:
                        print(flattened_json.to_csv())
                elif json_:
                    sl_helpers.handle_json_output(response, raw)
                else:
                    sl_console.echo_indicator_ipaddr(response, ipaddr)
            else:
                click.echo("An API call error occurred")
                sys.exit(1)
        
if __name__ == "__main__":
    main()
