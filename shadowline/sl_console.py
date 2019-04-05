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

