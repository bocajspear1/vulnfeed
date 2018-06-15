from datetime import datetime, timedelta

from database import Client

import re

# 'day' must be datetime
def get_reports(day):
    reports = []
    day = datetime.combine(day, datetime.min.time())
    start = day
    end = day + timedelta(days=1) - timedelta(seconds=1)
    print(start)
    print(end)
    cursor = Client.vulnreports.find({"date": {"$gte": start, "$lt": end}})
    for report in cursor:
        reports.append({"id": report['report_id'], "title": report['raw_title'], "contents": report['raw_contents'], "link": report['link'], "source": report.get('source', "?")})
    return reports

def get_report(report_id):
    if not re.match(r"[a-fA-Z0-9]+", report_id):
        return None
    else:
        return Client.vulnreports.find_one({"report_id": report_id})