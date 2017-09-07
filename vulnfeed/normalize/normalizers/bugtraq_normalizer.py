from ..rss_normalizer import RSSNormalizer


class BugTraqNormalizer(RSSNormalizer):

    def __init__(self):
        super().__init__("BugTraq", "http://seclists.org/rss/bugtraq.rss")

    def parse_entry(self, title, entry):
        return title, entry

