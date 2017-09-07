from ..rss_normalizer import RSSNormalizer


class NISTGovNormalizer(RSSNormalizer):

    def __init__(self):
        super().__init__("NISTGov", "https://nvd.nist.gov/download/nvd-rss.xml")

    def parse_entry(self, title, entry):
        return title, entry

