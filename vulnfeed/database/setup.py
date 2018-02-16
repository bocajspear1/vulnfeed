# Ensure the indexes are all set
from database import Client
from pymongo import ASCENDING

def _has_unique_index(index_list, index_name):
    for index in index_list:
        for key in index_list[index]['key']:
            if key[0] == index_name and index_list[index]['unique'] is True:
                return True
    return False

def _ensure_unique_index(collection, index):
    index_list = Client[collection].index_information()
    if not _has_unique_index(index_list, index):
        print(collection + " does not have index " + index)
        Client[collection].create_index([(index, ASCENDING)], unique=True)

def setup_database():
    user_indexes = Client.users.index_information()

    _ensure_unique_index("users", "email")
    _ensure_unique_index("vulnreports", "report_id")
    _ensure_unique_index("login_attempts", "address")

    