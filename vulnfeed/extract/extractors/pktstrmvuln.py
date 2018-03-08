from ..rss_extractor import RSSExtractor

class PktStrmRSSExtractor(RSSExtractor):

    def __init__(self):
        super().__init__("PacketStorm", "https://rss.packetstormsecurity.com/files/tags/vulnerability/")

    def run(self):
        entries = self.get_rss_entries()
        return entries

