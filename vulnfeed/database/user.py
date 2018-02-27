
from bson.objectid import ObjectId
import pymongo.errors as mongo_errors
import re
import datetime

from database import Client
from passlib.hash import pbkdf2_sha256

def get_users(start=0, limit=50):
    user_chunk = []
    user_chunk_cursor = Client.users.find({}).skip(start).limit(limit)
    for item in user_chunk_cursor:
        user_chunk.append(str(item['email']))
    return user_chunk


class User:

    def __init__(self, email):
        doc = Client.users.find_one({"email": email})

        self.email = email
        self.rules = []
        self.hash = None
        self.rules = []
        self.days = []
        self.last_run = 0

        if doc:
            self.rules = doc['rules']
            self.hash = doc['password']
            self.days = doc['days']
            self.last_run = doc['last_run']

    def set_days(self, new_days):
        if not isinstance(new_days, list):
            return 
        for item in new_days:
            if not isinstance(item, int):
                return
        
        self.days = new_days
            
    def set_rules(self, new_rules):
        valid_list = []
        for rule in new_rules:
            if re.match(r"^[0-9a-zA-Z]+$", rule['id']):
                valid_list.append(rule)
        
        self.rules = valid_list
        
  
    def update(self):
        new_data = {
            "rules": self.rules,
            "days": self.days,
            "last_run": self.last_run
        }
        Client.users.update({"email": self.email}, {"$set": new_data}, multi=False, upsert=False)

    def get_rules(self):
        return self.rules

    def get_days(self):
        return self.days

    def login(self, password):
        if self.hash is None:
            return False
    
        return pbkdf2_sha256.verify(password, self.hash)

    @classmethod
    def new_user(cls, email, password):
        user_coll = Client.users
        try:
            user_coll.insert_one({
                "email": email,
                "password":  pbkdf2_sha256.hash(password),
                "rules": [],
                "last_run": 0,
                "days": [6]
            })
        except mongo_errors.DuplicateKeyError:
            print("Dup key!")
            return None
        return cls(email)