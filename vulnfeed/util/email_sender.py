import os

import emails
from emails.template import JinjaTemplate 

from config import Config

CONFIG = Config()

def send_email(template, subject, data_map, recipient):
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "email_templates", template)

    smtp_config = {
        'host': CONFIG.smtp_host,
        'port': CONFIG.smtp_port,
        'user': CONFIG.smtp_user,
        'password': CONFIG.smtp_pass,
        'ssl': True
    }

    message = emails.Message(html=JinjaTemplate(open(template_path).read()), subject=subject, mail_from=("VulnFeed Agent", "vulnfeed@j2h2.com"))

    if CONFIG.has_dkim:
        message.dkim(key=open(CONFIG.dkim_privkey), domain=CONFIG.dkim_domain, selector=CONFIG.dkim_selector)


    response = message.send(render=data_map, to=recipient, smtp=smtp_config)

    return response