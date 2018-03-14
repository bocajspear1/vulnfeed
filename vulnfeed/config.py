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
        self.domain = raw_config['domain']
        self.email_salt = raw_config['email_salt']

        self.has_dkim = False
        self.dkim_privkey = ""
        self.dkim_domain = ""
        self.dkim_selector = ""
        if raw_config['dkim']:
            self.has_dkim = True
            self.dkim_privkey = raw_config['dkim']['privkey']
            if not os.path.exists(self.dkim_privkey):
                raise OSError("DKIM key not found!")
            self.dkim_domain = raw_config['dkim']['domain']
            self.dkim_selector = raw_config['dkim']['selector']
        

if __name__ == "__main__":
    config = Config()