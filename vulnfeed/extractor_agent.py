# This is the main file for the extractor. This should be run via cron.

import dateparser
from database import Client
import pymongo.errors as mongo_errors


from extract.extractors.bugtraq import BugTraqRSSExtractor
from extract.extractors.nistgov import NISTGovRSSExtractor
from extract.extractors.uscert import USCERTExtractor

EXTRACTORS = (BugTraqRSSExtractor, NISTGovRSSExtractor, USCERTExtractor)

class VulnFeedExtractorAgent():

    def run(self):
        vulnreports = Client.vulnreports

        added_count = 0

        for extractor_class in EXTRACTORS:
            extractor = extractor_class()
            entries = extractor.run()
            for entry in entries:
                try:
                    entry['date'] = dateparser.parse(entry['date'])
                    vulnreports.insert_one(entry)
                    added_count += 1
                except mongo_errors.DuplicateKeyError:
                    pass

        print(str(added_count) + " added")

if __name__ == "__main__":
    agent = VulnFeedExtractorAgent()
    agent.run()

