# This is the part of the code that sends the emails

import os
import threading
from datetime import datetime, timedelta

import emails
from emails.template import JinjaTemplate 

from database.user import get_users, User
from database.feed import get_feed_reports
from database.rules import fill_rules
from scorer.parser import VulnFeedRuleParser

from config import Config

CONFIG = Config()

# Sender master breaks users off into groups of 50 to be proccessed on different threads
class SenderMaster():
    def __init__(self):
        self.threads = []
    
    def start_senders(self):

        offset = 0
        length = 50
        user_chunk = get_users(offset, length)
        while len(user_chunk) > 0:
            
            worker_thread = SenderWorker(user_chunk)
            worker_thread.start()
            self.threads.append(worker_thread)

            offset += length
            user_chunk = get_users(offset, length)

        for thread in self.threads:
            thread.join()

# Works on a chunk of users
class SenderWorker(threading.Thread):   
    def __init__(self, user_chunk):
        threading.Thread.__init__(self)
        self.user_chunk = user_chunk

    def check_report(self, report_map, report, rules):
        for rule_item in rules:

            parser = VulnFeedRuleParser()
            parser.parse_rule(rule_item['rule'])

            title_score, _ = parser.process_text(report['title'], report['title_freq'])
            print(title_score)
            contents_score, _ = parser.process_text(report['contents'], report['contents_freq'])
            print("Score: ", contents_score)

            small_report = {
                "title": report['raw_title'],
                "contents": report['raw_contents'],
                "link": report['link'],
            }

            if not report['id'] in report_map:
                report_map[report['id']] = {
                    "report": small_report,
                    "score": 0
                }
            
            report_map[report['id']]['score'] += contents_score + (title_score * 2)

    def process_user(self, user_email):
        # Get object
        u = User(user_email)
        days_to_run = u.get_days()
        last_day = u.last_run
        current_time = datetime.utcnow()
        current_day = int(current_time.strftime("%w")) + 1
        day_diff = 2
        if last_day > 0:
            if last_day > current_day:
                current_day += 7
            day_diff = current_day - last_day

        
        # Get reports between the time requested plus some buffer time
        query_time = current_time - timedelta(hours=(day_diff*24)+4)
        reports = get_feed_reports(query_time)

        rules = u.get_rules()
        filled_rules = fill_rules(rules)

        report_map = {}

        for report in reports:
            self.check_report(report_map, report, filled_rules)


        

        sorted_reports = sorted(report_map, key=lambda item: report_map[item]['score'], reverse=True)

        for item in sorted_reports:
            print(report_map[item]['score'])
            print(report_map[item]['report']['title'])

        # high_reports = []
        # medium_reports = []
        # low_reports = []
        # report_count = 0

        # for report_id in report_map:
        #     score = report_map[report_id]['score']
        #     report = report_map[report_id]['report']
        #     report_count += 1
        #     if score == 0:
        #         low_reports.append(report)
        #     else:
        #         high_reports.append(report)

        # render_map = {
        #     "vulncount": report_count,
        #     "scored_reports": high_reports,
        #     "unscored_reports": medium_reports
        # }
        # template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", 'email_template.html')

        # smtp_config = {
        #     'host': CONFIG.smtp_host,
        #     'port': CONFIG.smtp_port,
        #     'user': CONFIG.smtp_user,
        #     'password': CONFIG.smtp_pass,
        #     'ssl': True
        # }

        # m = emails.Message(html=JinjaTemplate(open(template_path).read()),  text="hi there",  subject="VulnFeed Test", mail_from=("VulnFeed Agent", "vulnfeed@j2h2.com"))
        # response = m.send(render=render_map, to=user_email, smtp=smtp_config)
        # print(response)

    # Process each user
    def run(self):
        for user_email in self.user_chunk:
            self.process_user(user_email)

sm = SenderMaster()
sm.start_senders()