
from bson.objectid import ObjectId
import pymongo.errors as mongo_errors
import re
from datetime import datetime, date, timedelta

from database import Client
from passlib.hash import pbkdf2_sha256
from passlib import pwd

def get_users(start=0, limit=50):
    user_chunk = []
    user_chunk_cursor = Client.users.find({"confirmed": True}).skip(start).limit(limit)
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
        self.verify_token = ""
        self._confirmed = False
        self.last_status = "None"

        if doc:
            self.rules = doc['rules']
            self.hash = doc['password']
            self.days = doc['days']
            self.last_run = doc['last_run']
            self.verify_token = doc.get("verify_token", "")
            self._confirmed = doc.get("confirmed", True)
            self.last_status = doc.get("last_status")

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
  
    def set_confirmed(self):
        self._confirmed = True

    def is_confirmed(self):
        return self._confirmed

    def update(self):
        new_data = {
            "rules": self.rules,
            "days": self.days,
            "last_run": self.last_run,
            "verify_token": self.verify_token,
            "confirmed": self._confirmed,
            "password": self.hash,
            "last_status": self.last_status
        }
        Client.users.update({"email": self.email}, {"$set": new_data}, multi=False, upsert=False)

    def delete(self):
        Client.users.remove({"email": self.email})

    def get_rules(self):
        return self.rules

    def get_days(self):
        return self.days

    def login(self, password):
        if self.hash is None:
            return False
    
        return pbkdf2_sha256.verify(password, self.hash)

    def new_password(self, password):
        self.hash = pbkdf2_sha256.hash(password)

    def get_last_run_date(self):
        current_time = datetime.combine(date.today(), datetime.min.time())
        current_day = int(current_time.strftime("%j"))

        year = datetime.now().year

        if current_day < self.last_run:
            year -= 1

        full_date = datetime(year, 1, 1) + timedelta(self.last_run - 1)
        return full_date

    @classmethod
    def new_user(cls, email, password):
        user_coll = Client.users
        current_time = datetime.combine(date.today(), datetime.min.time())
        try:
            user_coll.insert_one({
                "email": email,
                "password":  pbkdf2_sha256.hash(password),
                "rules": [],
                "last_run": int(current_time.strftime("%j")),
                "days": [6],
                "confirmed": False,
                "verify_token": ""
            })
        except mongo_errors.DuplicateKeyError:
            print("Dup key!")
            return None
        return cls(email)