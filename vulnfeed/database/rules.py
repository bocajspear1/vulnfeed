from database import Client
from bson.objectid import ObjectId
import bson.errors

def get_rules(filter_string):
    rules = []
    query = {}
    if filter_string != "":
        regex_string = ".*" + filter_string + ".*"
        query = { "name": {"$regex": regex_string, "$options": "i"} }
    print(query)
    cursor = Client.rules.find(query)
    for rule in cursor:
        rule['id'] = str(rule['_id'])
        del rule['_id']
        rules.append(rule)
    return rules

def fill_rules(rule_list):
    
    new_list = []
    for i in range(len(rule_list)):
        rule_id = rule_list[i]['id']
        rule = Client.rules.find_one({"_id": ObjectId(rule_id)})
        del rule['_id']
        new_item = rule_list[i].copy()
        new_item.update(rule)
        new_list.append(new_item)
        print("New Rule: ", new_item)

    return new_list

class Rule():
    def __init__(self, rule_id):
        try:
            self.data = Client.rules.find_one({"_id": ObjectId(rule_id)})
        except bson.errors.InvalidId:
            self.data = None

    @classmethod
    def new_rule(cls, name, rule_string, description):
        rules_coll = Client.rules
        
        result = rules_coll.insert_one({
            "name": name,
            "rule":  rule_string,
            "description": description
        })
        return cls(result.inserted_id)
        