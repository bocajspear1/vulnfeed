# VulnFeed

VulnFeed is a project born out of having so many vulnerabilities and so little time.

The goal of this project is to have a service that sorts through vulnerability reports to give you a single report that is organized by the applications and services you are interested in. This brings the stuff you care about out of the massive pile of vulnerabilities that are reported each day.

No more filled email inboxes and no more slow perusings of massive vulnerability lists.

## Development

This service is written in Python 3. It uses Flask for the frontend with Bootstrap.

This is currently very alpha-level stuff! Feel free to contribute.

## Process

VulnFeed collects data vulnerabilty feeds with **extractors** and creates a vulnerabilty **report**. **Reports** are placed in the database.

Each day, the **sender** processes each user, and checks if they have enabled an email for the day. If so, all reports since the last email, plus 12 hours is scored for the user based on the user's rules. The results are placed into an email and sent to the user.

## VulnFeed Rules

VulnFeed rules use a very simple language used to indicate what should be matched. It consists of words combined with operators. 

**Words** are simple strings, and must be all lowercase (the normalizer puts all text in lowercase). These strings should correspond to an actual complete word (a string seperated by spaces, -, or _) that you want to match in the report. If a report contains the complete word, the report receives a score. For example, if the word `vulnfeed` is in a rule, it will match a report with `bug report for vulnfeed`, but not `bug report for vulnfeedinator`.

Words can be combined with operators for different effects. There are three binary operators (requires two words):

* AND - Both words in this operation must be in the report
* OR - The report must have at least one word in the report
* ANDOR - The report must have at least one word in the report, but if both are present in the order given in the rule, the score is doubled.

## Contributers

* Jacob Hartman - jacob (at) j2h (dot) com
* YOUR NAME HERE
