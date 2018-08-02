import re

def is_valid_email(value):
    return re.match(r"^[^@$<>;'\"]+@[^@$<>;'\"]+\.[^@$<>;'\"]+$", value)

def can_be_rule(value):
    return re.match(r"^[a-zA-Z:()0-9]+$", value)

def is_valid_id(value):
    return re.match(r"^[a-zA-Z0-9]+$", value)

def is_simple_string(value):
    return re.match(r"^[-a-zA-Z0-9.',!;:\"#=+ \t]+$", value)