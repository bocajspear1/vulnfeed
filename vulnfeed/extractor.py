import dateparser
from database import Client
import pymongo.errors as mongo_errors


from normalize.normalizers.bugtraq_normalizer import BugTraqNormalizer
from normalize.normalizers.nistgov import NISTGovNormalizer

ENABLED_NORMALIZERS = (BugTraqNormalizer, NISTGovNormalizer)

class VulnFeedExtractor():

    def run(self):
        vulnreports = Client.vulnreports

        added_count = 0

        for normalizer_class in ENABLED_NORMALIZERS:
            normalizer = normalizer_class()
            results = normalizer.get_data()
            for result in results:
                try:
                    result['date'] = dateparser.parse(result['date'])
                    vulnreports.insert_one(result)
                    added_count += 1
                except mongo_errors.DuplicateKeyError:
                    pass

        print(str(added_count) + " added")

ex = VulnFeedExtractor()
ex.run()