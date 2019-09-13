from . import sl_constants
from . import sl_helpers

from dotmap import DotMap

class SearchLightApi():
  settings = DotMap()
  
  def __init__(self, username, password):
    self.base_url = sl_constants.API_URL
    self.settings.USERNAME = username
    self.settings.PASSWORD = password

  def get_databreach_summary(self):

    json_data = sl_helpers.api_call("{}".format(sl_constants.DATABREACH_SUMMARY_CMD), 'get', self.settings)
    
    return json_data

  def get_databreach_list(self, breach_id):
    if breach_id:
        json_data = sl_helpers.api_call("{}{}".format(sl_constants.DATABREACH_FIND_ID_CMD, breach_id), 'get', self.settings, api_filter=sl_constants.DATABREACH_FILTER)
    else:
        json_data = sl_helpers.api_call("{}".format(sl_constants.DATABREACH_FIND_CMD), 'post', self.settings, api_filter=sl_constants.DATABREACH_FILTER)

    return json_data

  def get_databreach_usernames(self):
    json_data = sl_helpers.api_call("{}".format(sl_constants.DATABREACH_FIND_USERNAMES_CMD), 'post', self.settings, api_filter=sl_constants.DATABREACH_FILTER)

    return json_data

  def get_domain(self, domain):
    json_data = sl_helpers.api_call("{}{}".format(sl_constants.DOMAIN_LOOKUP_CMD, domain), 'get', self.settings)

    return json_data

  def get_domain_whois(self, domain):
    json_data = sl_helpers.api_call("{}{}".format(sl_constants.DOMAIN_WHOIS_CMD, domain), 'get', self.settings)

    return json_data

  def ip_whois_search(self, ipaddr):
    ip_whois_filter = sl_constants.IP_WHOIS_FILTER
    ip_whois_filter['query'] = ipaddr
    
    json_data = sl_helpers.api_call(sl_constants.SEARCH_CMD, 'post', self.settings, api_filter=ip_whois_filter)
    
    if json_data:
        ip_uuid = json_data['content'][0]['entity']['id']
        return ip_uuid
    return False
  
  def get_ipaddr_whois(self, ipaddr):
    ip_uuid = self.ip_whois_search(ipaddr)

    json_data = sl_helpers.api_call("{}{}".format(sl_constants.IPADDR_WHOIS_CMD, ip_uuid), 'get', self.settings)

    return json_data

  def get_cve(self, cve):
    cve_filter = sl_constants.CVE_FILTER
    cve_filter['query'] = cve

    json_data = sl_helpers.api_call(sl_constants.SEARCH_CMD, 'post', self.settings, api_filter=cve_filter)

    return json_data

  def get_cve_priority(self, cve):
    cve_filter = sl_constants.CVE_PRIORITY_FILTER
    cve_filter['query'] = cve

    json_data = sl_helpers.api_call(sl_constants.SEARCH_CMD, 'post', self.settings, api_filter=cve_filter)

    return json_data

  def get_profiles(self, cve):
    cve_filter = sl_constants.PROFILES_FILTER
    cve_filter['query'] = cve

    json_data = sl_helpers.api_call(sl_constants.SEARCH_CMD, 'post', self.settings, api_filter=cve_filter)

    return json_data

  def get_intel_incident(self, cve):
    cve_filter = sl_constants.INTEL_INCIDENT_FILTER
    cve_filter['query'] = cve

    json_data = sl_helpers.api_call(sl_constants.SEARCH_CMD, 'post', self.settings, api_filter=cve_filter)

    return json_data
  
  def get_threats(self, incident_id, iocs):
    if iocs:
      json_data = sl_helpers.api_call("{}{}/iocs".format(sl_constants.INTELTHREATS_CMD, incident_id), 'post', self.settings, api_filter=sl_constants.IOCS_FILTER)
    elif incident_id:
      json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELTHREATS_CMD, incident_id), 'get', self.settings, api_filter=sl_constants.THREAT_FILTER)
    else:
      json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELTHREATS_CMD, sl_constants.INTELTHREATS_FIND_CMD), 'post', self.settings, api_filter=sl_constants.THREAT_FILTER)

    return json_data

  def get_incidents(self, incident_id):
    json_data = ""
    
    if incident_id:
      json_data = sl_helpers.api_call("{}{}".format(sl_constants.INCIDENTS_CMD, incident_id), 'get', self.settings)
    else:
      json_data = sl_helpers.api_call("{}{}".format(sl_constants.INCIDENTS_CMD, sl_constants.INCIDENTS_FIND_CMD), 'get', self.settings)

    return json_data

  def get_intel(self, incident_id, iocs):
    if iocs:
      json_data = sl_helpers.api_call("{}{}/iocs".format(sl_constants.INTELINCIDENTS_CMD, incident_id), 'post', self.settings, api_filter=sl_constants.IOCS_FILTER)
    elif incident_id:
      json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELINCIDENTS_CMD, incident_id), 'get', self.settings, api_filter=sl_constants.THREAT_FILTER)
    else:
      json_data = sl_helpers.api_call("{}{}".format(sl_constants.INTELINCIDENTS_CMD, sl_constants.INTELINCIDENTS_FIND_CMD), 'post', self.settings, api_filter=sl_constants.INTEL_FILTER)

    return json_data

  def get_indicators(self, ipaddr):
    search_cmd = "search/find"
    search_filter = {"filter":{"dateRange":"ALL","tags":[],"types":["INDICATOR_FEED"]},"pagination":{"offset":0,"size":25},"sort":{"property":"relevance","direction":"DESCENDING"},"query":str(ipaddr),"facets":["RESULTS_TYPE"]}
    
    json_data = sl_helpers.api_call(search_cmd, 'post', self.settings, api_filter=search_filter)

    return json_data

