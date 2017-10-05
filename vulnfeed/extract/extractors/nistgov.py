from ..rss_extractor import RSSExtractor

class NISTGovRSSExtractor(RSSExtractor):

    def __init__(self):
        super().__init__("NISTGov", "https://nvd.nist.gov/download/nvd-rss.xml")

    def run(self):
        entries = self.get_rss_entries()
        return entries

