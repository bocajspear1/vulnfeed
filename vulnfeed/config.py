import os
import json

class Config():
    def __init__(self):
        config_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))
        self.config_file = os.path.join(config_dir, "config.json")
        if not os.path.exists(self.config_file):
            raise OSError("config.json not found!")
        raw_config = json.loads(open(self.config_file).read())
        self.smtp_host = raw_config['smtp']['host']
        self.smtp_port = raw_config['smtp']['port']
        self.smtp_user = raw_config['smtp']['user']
        self.smtp_pass = raw_config['smtp']['password']
        self.mongodb_string = raw_config['mongodb']
        self.secret = raw_config['secret']
        self.debug = raw_config['debug']
        self.recaptcha_secret = raw_config['recaptcha']['secret']
        self.recaptcha_sitekey = raw_config['recaptcha']['sitekey']
        self.admin_email = raw_config['admin_email']
        

if __name__ == "__main__":
    config = Config()