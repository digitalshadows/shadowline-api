from blessed import Terminal

blessed_t = Terminal()

def echo_databreach_summary(json_data):
    print("{} {}".format(blessed_t.blue("Total Breaches:"), blessed_t.white("{}".format(json_data['totalBreaches']))))
    for breach in json_data['breachesPerDomain']:
        print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("{} breaches for domain {}".format(breach['count'], breach['key'])))
    print("{} {}".format(blessed_t.blue("Total Usernames:"), blessed_t.white("{}".format(json_data['totalUsernames']))))
    for usernames in json_data['usernamesPerDomain']:
        print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("{} usernames for domain {}".format(usernames['count'], usernames['key'])))

def echo_databreach_list(json_data):
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

def echo_databreach_usernames(json_data):
    print(blessed_t.blue("Total Usernames"), blessed_t.white("{}".format(len(json_data['content']))))
    for row in json_data['content']:
        print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("username"), blessed_t.cyan("{}".format(row['username'])), blessed_t.yellow("breach count"), blessed_t.cyan("{}".format(row['breachCount'])))

def echo_domain_lookup(json_data):
    print(blessed_t.blue("Results for domain"), blessed_t.white("{}".format(json_data['dnsZone']['name'])), blessed_t.blue("from DNS server"), blessed_t.white("{}".format(json_data['dnsServerIpAddress'])))
    for record in json_data['dnsZone']['records']:
        if 'type' in record:
            print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("type"), blessed_t.cyan("{}".format(record['type'])), blessed_t.yellow("data"), blessed_t.cyan("{}".format(record['data'])))

def echo_domain_whois(json_data):
    if 'registrar' in json_data:
        print(blessed_t.blue("Results for domain"), blessed_t.green("{}".format(json_data['domain'])), blessed_t.blue("registered by"), blessed_t.white("{}".format(json_data['registrar'])))
    else:
        print(blessed_t.blue("Results for domain"), blessed_t.green("{}".format(json_data['domain'])))

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
            print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("organization"), blessed_t.cyan("{}".format(json_data['registrant']['organization'])))
    else:
        print("Registrant data missing, suggest using --json to review the raw output")

def echo_ipaddr_whois(json_data, ip_addr):
    print(blessed_t.blue("IP address"), blessed_t.green("{}".format(ip_addr)))
    print(blessed_t.move_right, blessed_t.move_right, blessed_t.yellow("NetName"), blessed_t.cyan(json_data['netName']), blessed_t.yellow("Country"), blessed_t.cyan(json_data['countryName']), blessed_t.yellow("IP range start"), blessed_t.cyan(json_data['ipRangeStart']), blessed_t.yellow("IP range end"), blessed_t.cyan(json_data['ipRangeEnd']))

def echo_cve_search(json_data, cve):
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
                        cpe_list.append(cpe)
                
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
