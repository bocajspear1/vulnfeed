# This is the part of the code that sends the emails

import os
import threading
from datetime import datetime, timedelta, date
import calendar
import re
import time

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
            contents_score, words = parser.process_text(report['contents'], report['contents_freq'])
            print(words)
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
            
            base_score = contents_score + (title_score * 2)

            if rule_item['weight'] == 'high':
                base_score *= 2
            elif rule_item['weight'] == 'medium':
                base_score += (base_score * 0.5)

            report_map[report['id']]['score'] += base_score
            
            if contents_score > 0:

                for word in words:
                    # Check if contains HTML
                    if "<" in report_map[report['id']]['report']['contents']:
                        boldify = re.compile('([>][^<]+)(' + word + ')', re.IGNORECASE)
                        report_map[report['id']]['report']['contents'] = boldify.sub(r"\1<strong>\2</strong>", 
                                                    report_map[report['id']]['report']['contents'])
                    else:
                        boldify = re.compile('(' + word + ')', re.IGNORECASE)
                        report_map[report['id']]['report']['contents'] = boldify.sub(r"<strong>\1</strong>", 
                                                    report_map[report['id']]['report']['contents'])
                    

    def process_user(self, user_email):
        # Get object
        u = User(user_email)
        days_to_run = u.get_days()
        # Last run is day of year
        last_day = u.last_run

        # Get the current day
        current_time = datetime.combine(date.today(), datetime.min.time())
        current_day = int(current_time.strftime("%w")) + 1
        current_day_of_year = int(current_time.strftime("%j"))

        # Check if today is a day set by the user
        if current_day not in days_to_run:
            return

        # Check if same day
        if current_day_of_year == last_day:
            return

        day_diff = 2
        if last_day > 0:
            # If the last day is greater than the current day
            # we have had a new year!
            if last_day > current_day_of_year:
                leap_day = 0
                if calendar.isleap(current_time.year - 1):
                    leap_day = 1
                day_diff = (current_day_of_year + 365 + leap_day) - last_day
            else:
                day_diff = current_day_of_year - last_day

        
        # Get reports between the time requested plus some buffer time
        query_time = current_time - timedelta(hours=(day_diff*24)+4)
        reports = get_feed_reports(query_time)

        # Get rule data
        rules = u.get_rules()
        filled_rules = fill_rules(rules)

        # Score the reports
        report_map = {}
        for report in reports:
            self.check_report(report_map, report, filled_rules)

        # Sort the reports
        sorted_reports = sorted(report_map, key=lambda item: report_map[item]['score'], reverse=True)

        # Seperate reports into scored and unscored
        scored_reports = []
        unscored_reports = []

        for item in sorted_reports:
            if report_map[item]['score'] > 0:
                scored_reports.append(report_map[item]['report'])
            else:
                unscored_reports.append(report_map[item]['report'])

        # for item in sorted_reports:
        #     print(report_map[item]['score'])
        #     print(report_map[item]['report']['contents'])

        report_count = len(sorted_reports)
       
        # Prepare to render the email template
        render_map = {
            "vulncount": report_count,
            "scored_reports": scored_reports,
            "unscored_reports": unscored_reports
        }
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", 'email_template.html')

        smtp_config = {
            'host': CONFIG.smtp_host,
            'port': CONFIG.smtp_port,
            'user': CONFIG.smtp_user,
            'password': CONFIG.smtp_pass,
            'ssl': True
        }

        m = emails.Message(html=JinjaTemplate(open(template_path).read()), subject="VulnFeed Report for " + time.strftime("%m/%d/%Y"), mail_from=("VulnFeed Agent", "vulnfeed@j2h2.com"))
        response = m.send(render=render_map, to=user_email, smtp=smtp_config)
        print(response)

        # Update the users last sent day
        u.last_run = current_day_of_year
        u.update()

    # Process each user
    def run(self):
        for user_email in self.user_chunk:
            self.process_user(user_email)

sm = SenderMaster()
sm.start_senders()