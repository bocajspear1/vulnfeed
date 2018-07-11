import datetime

import defusedxml.ElementTree as ET
import requests
import hashlib
import re

from .extractor import Extractor

class RSSExtractor(Extractor):
    
    def __init__(self, name, url):
        super().__init__()
        self.name = name
        self.url = url

    # Clean out namespaces
    def clean_tag(self, tag):
        return re.sub('{.*}', '', tag, count=1)
    
    def get_rss_entries(self):
        result_list = []

        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0',
        }

        feed = requests.get(self.url, headers)

        if feed.status_code == 200:
            # Remove any namespaces
            rssstring = re.sub(' xmlns="[^"]+"', '', feed.text, count=1)

            feed_xml = ET.fromstring(rssstring)

            if feed_xml.find('channel'):
                if feed_xml[0].find('item'):
                    for elem in feed_xml[0]:
                        tag = self.clean_tag(elem.tag)
                        if tag == "item":
                            result_list.append(self.parse_item(elem))

            for elem in feed_xml:
                tag = self.clean_tag(elem.tag)
                if tag == "item":
                    result_list.append(self.parse_item(elem))
        else:
            print(feed.status_code)
            return []

        return result_list

    def parse_item(self, item):

        entry_data = {
            "report_id": "",
            "title": "",
            "source": self.name,
            "raw_title": "",
            "title_freq": "",
            "contents": "",
            "raw_contents": "",
            "contents_freq": {},
            "link": "",
            "date": None
        }

        for child in item:
            tag = self.clean_tag(child.tag)
            if tag == "title":
                entry_data['title'] = self.normalizer.normalize_text(child.text)
                entry_data['raw_title'] = child.text
            elif tag == "description":
                entry_data['contents'] = self.normalizer.normalize_text(child.text)
                entry_data['raw_contents'] = child.text
            elif tag == "link":
                entry_data['link'] = child.text
            elif tag == "pubDate" or tag == "date":
                entry_data['date'] = child.text

        

        entry_data['title_freq'] = self.normalizer.get_word_frequency(entry_data['title'])
        entry_data['contents_freq'] = self.normalizer.get_word_frequency(entry_data['contents'])

        entry_data['report_id'] = hashlib.sha256((self.name + entry_data['title'] + entry_data['date'] + entry_data['link']).encode()).hexdigest()

        return entry_data