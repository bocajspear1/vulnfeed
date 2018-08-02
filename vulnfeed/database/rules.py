from database import Client
from bson.objectid import ObjectId
import bson.errors
import hashlib

def get_rules(filter_string="", user=""):
    rules = []
    query = {}
    if filter_string != "":
        regex_string = ".*" + filter_string + ".*"
        query = { "$or": [
            {"name": {"$regex": regex_string, "$options": "i"}}, 
            {"description": {"$regex": regex_string, "$options": "i"}}
        ] }
    if user != "":
        query = { "owner": user }
    cursor = Client.rules.find(query)
    for rule in cursor:
        rule['id'] = str(rule['_id'])
        del rule['_id']
        rules.append(rule)
    return rules

# Used to extend of list of just IDs with all rule information.
# Rules are stored like this with users
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
        object.__setattr__(self, '_data', {})
        object.__setattr__(self, 'id', None)
        
        try:
            self._data = Client.rules.find_one({"_id": ObjectId(rule_id)})
            self.id = rule_id
        except bson.errors.InvalidId:
            pass

    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        elif name in ['suggestions', 'history']:
            return []
        else:
            raise AttributeError(name + " attribute not found")

    def __setattr__(self, name, value):
        if name in ['history', 'suggestions', 'rule']:
            raise AttributeError(name + " cannot be set manually")

        if name in self._data:
            self._data[name] = value
        elif name in self.__dict__:
            self.__dict__[name] = value
        else:
            raise AttributeError(name + " attribute not found")

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
        if 'history' not in self._data:
            self._data['history'] = []
        
        self._data['history'].append(self._data['rule'])
        self._data['rule'] = new_rule_string
        return True

    def add_suggestion(self, user_id, suggestion_string):
        if 'suggestions' not in self._data:
            self._data['suggestions'] = []

        # Made suggestion id
        suggest_id = hashlib.sha1((user_id + suggestion_string).encode()).hexdigest()

        # Check this is not a duplicate
        for suggestion in self._data['suggestions']:
            if suggestion['suggest_id'] == suggest_id:
                return False
        
        self._data['suggestions'].append({"suggest_id": suggest_id, "user_id": user_id, "rule": suggestion_string, 'hidden': False})
        return True

    def hide_suggestion(self, suggest_id):
        for suggestion in self._data['suggestions']:
            if suggestion['suggest_id'] == suggest_id:
                suggestion['hidden'] = True

    def update(self):
        Client.rules.update({"_id": ObjectId(self.id)}, {"$set": self._data}, multi=False, upsert=False)
        