from datetime import datetime, timedelta

from database import Client

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
        reports.append({"title": report['raw_title'], "contents": report['contents'], "link": report['link'], "source": report.get('source', "?")})
    print(len(reports))
    return reports