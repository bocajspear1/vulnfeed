from database import Client
from bson.objectid import ObjectId

def get_rules():
    rules = []
    cursor = Client.rules.find({})
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
        doc = Client.users.find_one({"_id": ObjectId(rule_id)})

    @classmethod
    def new_rule(cls, name, rule_string, description):
        print("New Rule")
        rules_coll = Client.rules
        
        result = rules_coll.insert_one({
            "name": name,
            "rule":  rule_string,
            "description": description
        })
        return cls(result.inserted_id)
        