from ..rss_extractor import RSSExtractor


class USCERTExtractor(RSSExtractor):

    def __init__(self):
        super().__init__("USCERT", "https://www.us-cert.gov/ncas/current-activity.xml")

    def run(self):
        entries = self.get_rss_entries()
        return entries