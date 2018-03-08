# This is the main file for the extractor. This should be run via cron.

import dateparser
from database import Client
import pymongo.errors as mongo_errors

from util.email_sender import send_email

from config import Config
CONFIG = Config()

class VulnFeedExtractorAgent():

    def run(self):
        email_message = ""
        status = "Unknown"
        try:

            from extract.extractors.bugtraq import BugTraqRSSExtractor
            from extract.extractors.nistgov import NISTGovRSSExtractor
            from extract.extractors.uscert import USCERTExtractor
            from extract.extractors.pktstrmvuln import PktStrmRSSExtractor

            EXTRACTORS = (BugTraqRSSExtractor, NISTGovRSSExtractor, USCERTExtractor, PktStrmRSSExtractor)

            vulnreports = Client.vulnreports

            added_count = 0
            duplicate_count = 0

            for extractor_class in EXTRACTORS:
                extractor = extractor_class()
                entries = extractor.run()
                for entry in entries:
                    try:
                        entry['date'] = dateparser.parse(entry['date'])
                        vulnreports.insert_one(entry)
                        added_count += 1
                    except mongo_errors.DuplicateKeyError:
                        duplicate_count += 1
                        pass
            email_message = str(added_count) + " added, " + str(duplicate_count) + " duplicates found"
            print(email_message)
            status = "Successful"
        except Exception as e:
            email_message = "Exception: " + str(e)
            print(email_message)
            status = "Failed"

        data_map = {
            "status": status, 
            "message": email_message
        }

        send_email("status_email.html", "Vulnfeed Extractor Status: " + status,  data_map, CONFIG.admin_email)

if __name__ == "__main__":
    agent = VulnFeedExtractorAgent()
    agent.run()

