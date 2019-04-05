### URL for the DS Portal
API_URL = "https://portal-digitalshadows.com/api/"
### Standard headers for all API requests
HEADERS = {"Content-Type":"application/vnd.polaris-v38+json", "Accept":"application/vnd.polaris-v38+json"}

### Standard filters for API requests
DATABREACH_FILTER = {"filter":{"published":"P6M","domainNamesOnRecords":[],"repostedCredentials":[]},"sort":{"property":"published","direction":"DESCENDING"}}
IP_WHOIS_FILTER = {"filter":{"dateRange":"ALL","tags":[],"types":["IP_WHOIS"]},"pagination":{"offset":0,"size":25},"sort":{"property":"relevance","direction":"DESCENDING"},"query":"","facets":["RESULTS_TYPE"]}
CVE_FILTER = {"filter":{"dateRange":"ALL","tags":[],"types":["VULNERABILITY_EXPLOIT"]},"pagination":{"offset":0,"size":25},"sort":{"property":"relevance","direction":"DESCENDING"},"query":"","facets":["RESULTS_TYPE"]}
THREAT_FILTER = {"filter":{"dateRange":"P6M","dateRangeField":"lastActive","tags":[],"tagOperator":"AND","threatLevels":[],"relevantToClientOnly":"false"},"sort":{"property":"lastActive","direction":"DESCENDING"},"pagination":{"size":12,"offset":0}}
IOCS_FILTER = {"filter":{},"sort":{"property":"value","direction":"ASCENDING"}}
INTEL_FILTER = {"filter":{"severities":[],"tags":[],"tagOperator":"AND","dateRange":"ALL","dateRangeField":"published","types":[],"withFeedback":"true","withoutFeedback":"true"},"sort":{"property":"date","direction":"DESCENDING"},"pagination":{"size":50,"offset":0}}

### Portal API endpoints
# Databreaches
DATABREACH_FIND_CMD = "data-breach/find"
DATABREACH_FIND_ID_CMD = "data-breach/"
DATABREACH_SUMMARY_CMD = "data-breach-summary"
DATABREACH_FIND_USERNAMES_CMD = "data-breach-usernames/find"
# Domains
DOMAIN_LOOKUP_CMD = "dns-lookup/"
DOMAIN_WHOIS_CMD = "domain-whois/"
# IP Addresses
IPADDR_WHOIS_CMD = "ip-whois/"
# Search
SEARCH_CMD = "search/find"
# Intel Threats
INTELTHREATS_CMD = 'intel-threats/'
INTELTHREATS_FIND_CMD = "find"
# Incidents
INCIDENTS_CMD = 'incidents/'
INCIDENTS_FIND_CMD = "find"
# Intel Incidents
INTELINCIDENTS_CMD = 'intel-incidents/'
INTELINCIDENTS_FIND_CMD = "find"
