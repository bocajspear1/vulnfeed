# VulnFeed
This is a project fir having so many vulnerabilities and so little time.
VulnFeed is a project born out of having so many vulnerabilities and so little time.

The goal of this project is to have a service that sorts through vulnerability reports to give you a single report that is organized by the applications and services you are interested in. This brings the stuff you care about out of the massive pile of vulnerabilities that are reported each day.

No more filled email inboxes and no more slow perusings of massive vulnerability lists.


## Development

This service is written in Python 3. It uses Flask for the frontend with Bootstrap.

This is currently very alpha-level stuff! Feel free to contribute.

## Install 

Install Python dependencies:
```
pip3 install -r dependencies.txt
```

Setup the database:
```
mongo < database-setup.js
```

Edit the config.
```
cp config.json.sample config.json
<EDITOR> config.json
```

### Production Install 

To generate a DKIM key, use `ssh-keygen` to generate a key. You'll need to set the DKIM DNS key similar to what's found in this article: https://support.rackspace.com/how-to/create-a-dkim-txt-record/

> If your're having trouble with your key not resolving in DNS, try using a 1024 sized key. Some DNS providers do not support the larger 2048 sized keys.

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

## Usage

VulnFeed consists of three main scripts:
* The web application - `vulnfeed/server.py` or `vulnfeed/wsgi.py`
* The feed extraction - `vulnfeed/extractor_agent.py` (Note that feed elements are imported only once, so if you run the extractor twice on the same day, you might get no new items)
* The email sender - `vulnfeed/sender.py`

The web server is standalone (mainly for testing) or under wsgi when in production. The other two are run independently. In production, you might use cron jobs to run these scripts at a certain time.

## Contributers

* Jacob Hartman - jacob (at) j2h (dot) com
* YOUR NAME HERE
