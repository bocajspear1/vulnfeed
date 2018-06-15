# Ensure the indexes are all set
from database import Client
from pymongo import ASCENDING, TEXT

def _has_unique_index(index_list, index_name):
    for index in index_list:
        for key in index_list[index]['key']:
            if key[0] == index_name and index_list[index]['unique'] is True:
                return True
    return False

# def _has_text_index(index_list, indexes):
#     print(index_list)
#     for index in index_list:
#         if "textIndexVersion" in index_list[index]:
#             for test_index in indexes:
#                 if test_index not in index_list[index]['weights']:
#                     return False
#             return True
                
#     return False

def _ensure_unique_index(collection, index):
    index_list = Client[collection].index_information()
    if not _has_unique_index(index_list, index):
        print(collection + " does not have index " + index)
        Client[collection].create_index([(index, ASCENDING)], unique=True)

# def _ensure_text_index(collection, indexes):
#     index_list = Client[collection].index_information()
#     if not _has_text_index(index_list, indexes):
#         print(collection + " does not have text index " + str(indexes))
#         index_list = []
#         for index in indexes:
#             index_list.append((index, TEXT))
#         Client[collection].create_index(index_list, default_language='english')

def setup_database():
    
    _ensure_unique_index("users", "email")
    _ensure_unique_index("vulnreports", "report_id")
    _ensure_unique_index("login_attempts", "address")
    # _ensure_text_index("rules", ['name', 'description', 'rule'])
    

    