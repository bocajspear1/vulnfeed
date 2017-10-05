from ..rss_extractor import RSSExtractor


class BugTraqRSSExtractor(RSSExtractor):

    def __init__(self):
        super().__init__("BugTraq", "http://seclists.org/rss/bugtraq.rss")

    def run(self):
        entries = self.get_rss_entries()
        return entries

