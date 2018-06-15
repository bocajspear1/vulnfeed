# A normalizer is used to parse text from vulnerability feeds into something useful

import os
import re

class Normalizer():

    def __init__(self):
        # Stores the entries from the source
        self.entries = []
        common_words_file = open(os.path.dirname(__file__) + "/dictionaries/common-words").read()
        self.common_words = common_words_file.split("\n")

    # Convert raw text into something a bit more parseable
    def normalize_text(self, data):

        data = data.lower()
        # Normalize links
        data = re.sub("<[ ]*a[ ]*[^>]*href[ ]*=[ ]*['\"]([^'\"]*)['\"][ ]*>([^><]*)<[ ]*/[ ]*a[ ]*>", r"\1 \2", data)
        # Remove separaters
        data = re.sub(r"[-_=.]{3,}", " ", data)
        # Strip out tags
        data = re.sub(r"</?[a-z]+>", " ", data)
        # Strip out puncuation and special chars
        data = re.sub(r"[,:;.\[\](){}$-]", " ", data)

        return data

    # Count out words, excluding common ones
    def get_word_frequency(self, data):
        return_map = {}
        space_split = re.split(r"[ \n\t]", data)
        for word in space_split:

            # Remove words that are just special characters
            if re.match(r"^[-=_{}\[\]()<>.,/\\:]+$", word):
                continue
        
            # Remove blanks and common words
            if word in self.common_words or word == "":
                continue

            to_add = [word]

            # For - and _ seperated words, count both combined and seperate
            if "-" in word or "_" in word:
                dash_split = re.split(r"[-_]", word)
                for section in dash_split:
                    if section.strip() != "":
                        to_add.append(section)

            for addition in to_add:
                if not addition in return_map:
                    return_map[addition] = 1
                else:
                    return_map[addition] += 1

        return return_map
    
    