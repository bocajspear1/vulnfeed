import datetime

import defusedxml.ElementTree as ET
import requests
import hashlib
import re

from .normalizer import Normalizer


class RSSNormalizer(Normalizer):
    
    def __init__(self, name, url):
        super().__init__()
        self.name = name
        self.url = url

    # Clean out namespaces
    def clean_tag(self, tag):
        return re.sub('{.*}', '', tag, count=1)


    
    def get_data(self):
        result_list = []
        feed = requests.get(self.url)

        if feed.status_code == 200:

            rssstring = re.sub(' xmlns="[^"]+"', '', feed.text, count=1)

            feed_xml = ET.fromstring(rssstring)

            if feed_xml.find('channel'):
                if feed_xml[0].find('item'):
                    for elem in feed_xml[0]:
                        tag = self.clean_tag(elem.tag)
                        if tag == "item":
                            self.parse_item(elem)

            for elem in feed_xml:
                tag = self.clean_tag(elem.tag)
                if tag == "item":
                    self.parse_item(elem)

            
        else:
            print(feed.status_code) 

        return self.entries

    def parse_entry(self, title, entry):
        return title, entry

    def parse_item(self, item):

        feed_data = {
            "report_id": "",
            "title": "",
            "title_freq": "",
            "contents": "",
            "contents_freq": {},
            "link": "",
            "date": None
        }

        for child in item:
            tag = self.clean_tag(child.tag)
            if tag == "title":
                feed_data['title'] = self.normalize_text(child.text)
                feed_data['raw_title'] = child.text
            elif tag == "description":
                feed_data['contents'] = self.normalize_text(child.text)
                feed_data['raw_contents'] = child.text
            elif tag == "link":
                feed_data['link'] = child.text
            elif tag == "pubDate" or tag == "date":
                feed_data['date'] = child.text

        feed_data['title'], feed_data['contents'] = self.parse_entry(feed_data['title'], feed_data['contents'])

        feed_data['title_freq'] = self.get_word_frequency(feed_data['title'])
        feed_data['contents_freq'] = self.get_word_frequency(feed_data['contents'])

        feed_data['report_id'] = hashlib.sha256((self.name + feed_data['title'] + feed_data['date'] + feed_data['link']).encode()).hexdigest()

        # print(feed_data['title'])
        # print(feed_data['title_freq'])
        self.entries.append(feed_data)