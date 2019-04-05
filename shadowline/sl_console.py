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
