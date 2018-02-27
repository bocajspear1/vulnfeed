# This is the main file for the extractor. This should be run via cron.

import dateparser
from database import Client
import pymongo.errors as mongo_errors

import emails
from emails.template import JinjaTemplate 

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

            EXTRACTORS = (BugTraqRSSExtractor, NISTGovRSSExtractor, USCERTExtractor)

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
            email_message = str(added_count) + " added"
            print(email_message)
            status = "Successful"
        except Exception as e:
            email_message = "Exception: " + str(e)
            print(email_message)
            status = "Failed"

        m = emails.Message(text=JinjaTemplate("Status: {{ status }}\n{{ message }}"),
                   subject=JinjaTemplate("Vulnfeed Extractor Status: {{ status }}"),
                   mail_from=("VulnFeed Agent", "vulnfeed@j2h2.com"))

        smtp_config = {
            'host': CONFIG.smtp_host,
            'port': CONFIG.smtp_port,
            'user': CONFIG.smtp_user,
            'password': CONFIG.smtp_pass,
            'ssl': True
        }
        
        response = m.send(render={"status": status, "message": email_message},
                          to=CONFIG.admin_email,
                          smtp=smtp_config)

if __name__ == "__main__":
    agent = VulnFeedExtractorAgent()
    agent.run()

