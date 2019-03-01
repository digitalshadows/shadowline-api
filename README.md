# shadowline

A Python CLI library for interfacing with the Digital Shadows Portal API.

Shadowline can be invoked with `shadowline`. It is written in Python 3.

## Installation

Shadowline can be installed on Linux by running from the project root:

```bash
sudo pip install .
```

Shadowline requires the following dependencies:

```none
netaddr==0.7.19
Click==7.0
Pygments==2.2.0
requests==2.18.4
retrying==1.3.3
blessed==1.15.0
pandas==0.24.1
```

## Usage

Shadowline uses the `click` text user interface and provides contextual help from the script itself:

```none
Usage: shadowline [OPTIONS] COMMAND [ARGS]...

  ShadowLine: A command-line API for Digital Shadows SearchLight

Options:
  --profile TEXT  Name of profile to use. 'DEFAULT' if not specified.
  -h, --help      Show this message and exit.

Commands:
  cve_search           Lookup a CVE
  databreach_list      Lists the details of a specific breach
  databreach_summary   Retrieve a summary of databreaches
  databreach_username  Lists usernames impacted by a specific breach
  domain_lookup        Perform a DNS lookup for a domain
  domain_whois         Lookup the domain WHOIS information for a domain
  incidents            Retrieve all incidents or an incident
  indicator            search for an IP address as an Indicator Of Compromise
  ipaddr_whois         Lookup the WHOIS information for an IP address
  setup_profile        Setup a profile to store API credentials
  threats              Look up a threat record
```

The first thing a user should do is to setup a profile to store their API credentials. Run:

```bash
$ shadowline setup_profile
```

You will be prompted to enter a profile name, username and password. It is recommended that if users only have one API account with the Digital Shadows portal that they name their profile 'DEFAULT'. This is the default profile name that is used for commands, if a profile is not explicitly set.

Example usage after credentials profile is setup:

```bash
shadowline databreach_summary # uses the DEFAULT profile credentials
shadowline --profile TEST databreach_summary # uses the TEST profile credentials
```

Credentials profiles are stored in the user's home directory in the following location:

```none
$HOME/.shadowline/profile
```

### Example (Databreach Summary)
  
#### Default summary output

```bash
$ shadowline databreach_summary

Total Breaches: 18
    17 breaches for domain example.com
    2 breaches for domain test.com
Total Usernames: 157
    156 usernames for domain example.com
    1 usernames for domain test.com
```

Shadowline queries will return results in a summary format by default, as shown in the example above. Shadowline also supports (pretty printed) JSON and CSV output (optionally to a file).

#### JSON pretty print

```bash
$ shadowline databreach_summary --json

{
    "breachesPerDomain": [
        {
            "count": 17,
            "key": "example.com"
        },
        {
            "count": 2,
            "key": "test.com"
        }
    ],
    "totalBreaches": 18,
    "totalUsernames": 157,
    "usernamesPerDomain": [
        {
            "count": 156,
            "key": "example.com"
        },
        {
            "count": 1,
            "key": "test.com"
        }
    ]
}
```

#### JSON raw

```bash
$ shadowline databreach_summary --json --raw

{"totalBreaches": 18, "totalUsernames": 157, "usernamesPerDomain": [{"key": "example.com", "count": 156}, {"key": "test.com", "count": 1}], "breachesPerDomain": [{"key": "example.com", "count": 17}, {"key": "test.com", "count": 2}]}
```

#### CSV raw

```bash
$ shadowline databreach_summary --csv

,totalBreaches,totalUsernames,usernamesPerDomain,breachesPerDomain
0,18,157,"{'key': 'example.com', 'count': 156}","{'key': 'example.com', 'count': 17}"
1,18,157,"{'key': 'test.com', 'count': 1}","{'key': 'test.com', 'count': 2}"
```

#### CSV output to file

```bash
$ shadowline databreach_summary --csv --output_file output.csv

# output is written to the specified file
```

The same format for choosing different types of output applies across all Shadowline commands.

### Example (gathering specific information on a data breach)

A list of all data breaches that affect an organization can be displayed with the following command:

```bash
$ shadowline databreach_list

Total Breaches 1
Title Report of data leak from apollo.io
    number of usernames impacted for organization 148
    breach published on 2018-10-08T09:12:15.255Z
    severity HIGH
    breach ID 5494173
```

To gain more information on the breach itself, the following command can be used:

```bash
$ shadowline databreach_list --breach_id 5494173

Title Report of data leak from apollo.io
    breach occurred on 2018-07-23
    severity HIGH
    breach ID 5494173
    data classes in breach
        data classes in breach EMAIL_ADDRESSES
        data classes in breach EMPLOYERS
        data classes in breach GEOGRAPHIC_LOCATIONS
        data classes in breach JOB_TITLES
        data classes in breach NAMES
        data classes in breach PHONE_NUMBERS
        data classes in breach SALUTATIONS
```

### Example (reviewing incidents)

A list of all incidents in the last 6 months can be retrieved with:

```bash
$ shadowline incidents
```

This will provide a list of the incident IDs. More specific information can be found with...

The raw incident information can be seen with `--json` or `--csv`.
