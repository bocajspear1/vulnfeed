# Base class for all extractors

import os
import re
from abc import ABCMeta, abstractmethod
from vulnfeed.util.normalizer import Normalizer

class Extractor(metaclass=ABCMeta):

    def __init__(self):
        # Stores the entries from the source
        self.entries = []
        self.normalizer = Normalizer()
    
    @abstractmethod
    def run(self):
        return NotImplemented
    