from pymongo import MongoClient
from config import Config
Client = MongoClient(Config().mongodb_string).vulnfeed