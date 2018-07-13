from database import Client
from bson.objectid import ObjectId
import bson.errors
import hashlib

def get_rules(filter_string="", user=""):
    rules = []
    query = {}
    if filter_string != "":
        regex_string = ".*" + filter_string + ".*"
        query = { "name": {"$regex": regex_string, "$options": "i"} }
    if user != "":
        query = { "owner": user }
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

    return new_list

class Rule():
    def __init__(self, rule_id):
        try:
            self.data = Client.rules.find_one({"_id": ObjectId(rule_id)})
            self.id = rule_id
        except bson.errors.InvalidId:
            self.data = None

    @classmethod
    def new_rule(cls, name, rule_string, description, owner):
        rules_coll = Client.rules
        
        result = rules_coll.insert_one({
            "name": name,
            "rule":  rule_string,
            "description": description,
            "owner": str(owner),
            "history": [],
            "suggestions": []
        })
        return cls(result.inserted_id)

    def update_rule_string(self, new_rule_string):
        if 'history' not in self.data:
            self.data['history'] = []
        
        self.data['history'].append(self.data['rule'])
        self.data['rule'] = new_rule_string
        return True

    def add_suggestion(self, user_id, suggestion_string):
        if 'suggestions' not in self.data:
            self.data['suggestions'] = []

        # Made suggestion id
        suggest_id = hashlib.sha1((user_id + suggestion_string).encode()).hexdigest()

        # Check this is not a duplicate
        for suggestion in self.data['suggestions']:
            if suggestion['suggest_id'] == suggest_id:
                return False
        
        self.data['suggestions'].append({"suggest_id": suggest_id, "user_id": user_id, "rule": suggestion_string, 'hidden': False})
        return True

    def hide_suggestion(self, suggest_id):
        print(suggest_id)
        for suggestion in self.data['suggestions']:
            if suggestion['suggest_id'] == suggest_id:
                suggestion['hidden'] = True

    def update(self):
        Client.rules.update({"_id": ObjectId(self.id)}, {"$set": self.data}, multi=False, upsert=False)
        