class SearchLightApi():
  def __init__(self, username, password):
    self.base_url = sl_constants.API_URL
    self.session = requests.Session()
    self.session.auth = (username, password)

  def get_databreach_summary():
    path = urllib.parse.urljoin(self.base_url, sl_constants.DATABREACH_SUMMARY_CMD)
    return self.session.get(path)
