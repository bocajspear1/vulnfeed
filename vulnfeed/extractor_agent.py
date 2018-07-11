# This is the main file for the extractor. This should be run via cron.

import argparse

import dateparser
import pymongo.errors as mongo_errors

from database import Client
from util.email_sender import send_email

from config import Config
CONFIG = Config()

class VulnFeedExtractorAgent():


    def run(self, noemail=False, debug=False):
        if noemail:
            print("NOTICE: Not sending email")

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
                if debug:
                    print(extractor_class.__name__)
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
        if not noemail:
            send_email("status_email.html", "Vulnfeed Extractor Status: " + status,  data_map, CONFIG.admin_email)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run VulnFeed extractors')
    parser.add_argument('-n', '--noemail', help='Dont\'t send an email when complete (for debugging and dev)', action='store_true')
    parser.add_argument('-d', '--debug', help='For debugging and dev', action='store_true')

    args = parser.parse_args()

    agent = VulnFeedExtractorAgent()
    agent.run(noemail=args.noemail, debug=args.debug)

