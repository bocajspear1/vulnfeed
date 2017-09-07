
from database import Client

def get_feed_reports(timelimit):
    reports=[]
    query = {"date": {"$gte": timelimit}}
    cursor = Client.vulnreports.find(query)
    for entry in cursor:
        entry['id'] = str(entry['_id'])
        del entry['_id']
        reports.append(entry)
    return reports
        