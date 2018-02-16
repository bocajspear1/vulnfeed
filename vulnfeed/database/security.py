import pymongo.errors as mongo_errors
import re
from datetime import datetime, timedelta

from database import Client

# Timeout before we subtract an attempt
TIMEOUT = timedelta(minutes=30)
# Allowed attempts before we lock out address
ATTEMPT_COUNT = 5

def address_failed_login(address):
    attempt_data = Client.login_attempts.find_one({"address": address})
    print(attempt_data)
    if not attempt_data:
        Client.login_attempts.insert({"address": address, "attempt_count": 1, "last_attempt": datetime.now()})
    else:
        count = attempt_data['attempt_count']
        
        if (datetime.now() - attempt_data['last_attempt']) > TIMEOUT:
            print("Timeout hit!")
            count = 0
        else:
            count += 1
        
        Client.login_attempts.update({"address": address}, {"$set": {"attempt_count": count, "last_attempt": datetime.now()}})
        if count > ATTEMPT_COUNT:
            return True
        else:
            return False

def clear_failed_login(address):
    Client.login_attempts.remove({"address": address})