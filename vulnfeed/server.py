# This is the web server for VulnFeed
from pymongo import MongoClient
from bson.objectid import ObjectId
import pymongo.errors as mongo_errors

from flask import Flask, flash, redirect, render_template, request, session, abort, jsonify
import os
import json
import re
import requests
from datetime import date, datetime
from itsdangerous import URLSafeTimedSerializer

from database.user import User
import database.rules as rules
from database.rules import Rule
import database.reports
from database.setup import setup_database
from scorer.parser import VulnFeedRuleParser

from util.email_sender import send_email
import util.string_validator as string_validator

from database.security import address_failed_login, clear_failed_login


from config import Config

conf = Config()

app = Flask(__name__)
app.secret_key = conf.secret

timed_serializer = URLSafeTimedSerializer(conf.secret)
setup_database()

# Home page
@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('info.html')
    else:
        return render_template('home.html')

# Signup Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if not string_validator.is_valid_email(request.form['email']):
            return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Invalid email address")
        elif request.form['email'] != request.form['email2']:
            return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Email addresses do not match!")
        elif request.form['password'] != request.form['password2']:
            return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Passwords do not match!")
        else:
            # Valid signup!

            # Captcha
            if conf.recaptcha_sitekey and conf.recaptcha_secret:
                captcha_response = request.form['g-recaptcha-response']
                captcha_verify = requests.post('https://www.google.com/recaptcha/api/siteverify', data = {'secret': conf.recaptcha_secret, 'response': captcha_response})
                captcha_verify_json = json.loads(captcha_verify.text)

                if captcha_verify_json['success'] is False:
                    return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Captcha failure")

            # Insert new user
            result = User.new_user(request.form['email'], request.form['password'])

            # Send verification email
            
            verify_token = timed_serializer.dumps(result.email, salt=conf.email_salt)

            url = conf.domain + "/verify/" + verify_token

            result.verify_token = verify_token

            result.update()

            render_map = {
                "url": url,
            }
            
            send_email("verify_email.html", "Verification for VulnFeed", render_map, result.email)
            
            if result:
                return render_template('success_to_login.html', message="Signup was successful. You should recieve an activation email to get started.")
            else:
                return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Could not create account. Perhaps an account of that name already exists?")
        
    else:
        return render_template('signup.html', sitekey=conf.recaptcha_sitekey)

# Verify page
@app.route('/verify/<token>', methods=['GET'])
def verify(token):
    try:
        email = timed_serializer.loads(token, salt=conf.email_salt, max_age=86400)
    except Exception as e:
        return "Could not parse token"

    user = User(email=email)

    if user.hash is not None and user.verify_token == token:
        user.set_confirmed()
        user.verify_token = ""
        user.update()
        return render_template('success_to_login.html', message="Your address has been verified. You can now login!")
    else:
        return "Invalid token"


# Forgot password page
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():

    if request.method == 'POST':
        if not re.match(r"[^@$<>;'\"]+@[^@$<>;'\"]+\.[^@$<>;'\"]+", request.form['email']):
            return render_template('forgot.html', sitekey=conf.recaptcha_sitekey, server_error="Invalid email address")
        else:
            # Captcha
            if conf.recaptcha_sitekey and conf.recaptcha_secret:
                captcha_response = request.form['g-recaptcha-response']
                captcha_verify = requests.post('https://www.google.com/recaptcha/api/siteverify', data = {'secret': conf.recaptcha_secret, 'response': captcha_response})
                captcha_verify_json = json.loads(captcha_verify.text)

                if captcha_verify_json['success'] is False:
                    return render_template('forgot.html', sitekey=conf.recaptcha_sitekey, server_error="Captcha failure")
            
            user = User(email=request.form['email'])

            if user.hash is None:
                return render_template('forgot.html', sitekey=conf.recaptcha_sitekey, server_error="Account not found")

            verify_token = timed_serializer.dumps(user.email, salt=conf.email_salt)

            url = conf.domain + "/resetpass/" + verify_token

            user.verify_token = verify_token
            user.update()

            render_map = {
                "url": url,
            }
            
            send_email("forget_email.html", "VulnFeed Password Reset", render_map, user.email)

            return render_template('forgot.html', sitekey=conf.recaptcha_sitekey, success_message="A password recover email has been sent to your email address")

    else:
        return render_template('forgot.html', sitekey=conf.recaptcha_sitekey)


@app.route('/resetpass/<token>', methods=['GET', 'POST'])
def resetpass(token):

    try:
        email = timed_serializer.loads(token, salt=conf.email_salt, max_age=7200)
    except Exception as e:
        return "Could not parse token"

    user = User(email=email)

    if user.verify_token != token:
        return "Invalid token"

    if request.method == 'POST':
        if request.form['password'] != request.form['password2']:
            return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Passwords do not match!")
        else:
            user.new_password(request.form['password'])
            user.verify_token = ""
            user.update()
        return redirect("/login", code=302) 
    else:

        if user.hash is not None:
            return render_template('resetpass.html', user_token=token)
        else:
            return "Invalid token"

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        if address_failed_login(request.remote_addr):
            return render_template('login.html', server_error="You have exceeded the number of fail logins. Try again later")
        
        user_email = request.form['email']
        if not string_validator.is_valid_email(user_email):
            session['logged_in'] = False
            session['user_email'] = ""
            message = "Incorrect user/password"

        message = ""
        user = User(email=user_email)

        if user.login(request.form['password']) and user.is_confirmed():
            session['logged_in'] = True
            session['user_email'] = user_email
            clear_failed_login(request.remote_addr)
            return redirect("/", code=302)
        # User doesn't exist
        elif user.hash == None:
            session['logged_in'] = False
            session['user_email'] = ""
            message = "Incorrect user/password"
        # User is not confirmed
        elif not user.is_confirmed():
            session['logged_in'] = False
            session['user_email'] = ""
            message = "You have not verified your email address"
        else:
            session['logged_in'] = False
            session['user_email'] = ""
            message = "Incorrect user/password"

        return render_template('login.html', server_error=message)
    else:
        return render_template('login.html')

# Report viewer page
@app.route('/report_viewer', methods=['GET'])
def report_viewer():
    if not session.get('logged_in'):
        return redirect("/login", code=302)

    day = request.args.get('day')
    date_obj = None

    
    if not day:
        date_obj = datetime.combine(date.today(), datetime.min.time())
    else:
        try:
            date_obj = datetime.strptime(day, '%Y-%m-%d').date()
        except:
            return render_template('report_view.html', server_error="Invalid date")
         
    reports = database.reports.get_reports(date_obj)
    return render_template('report_view.html', days_reports=reports)

# Report viewer page
@app.route('/last_report', methods=['GET'])
def last_report():
    if not session.get('logged_in'):
        return redirect("/login", code=302)

    user = User(email=session['user_email'])
    if user:
        return render_template('last_report.html', last_scored_reports=user.last_scored_list, last_unscored_reports=user.last_unscored_list)
    else:
        return "ERROR: User not found!"
    # 

# Profile page
@app.route('/profile', methods=['GET'])
def profile():
    if not session.get('logged_in'):
        return redirect("/login", code=302)

    user = User(email=session['user_email'])

    raw_data = json.dumps(user.get_minimized_raw(), indent=4, separators=(',', ': '))

    user_rules = rules.get_rules(user=user.id)

    return render_template('profile.html', 
                            email=user.email, 
                            last_status=user.last_status, 
                            rule_count=len(user.get_rules()),
                            last_sent=user.get_last_run_date().strftime('%m/%d/%Y'),
                            my_rules=user_rules,
                            raw_profile=raw_data)

# Delete page
@app.route('/delete', methods=['GET', 'POST'])
def delete():
    if not session.get('logged_in'):
        return redirect("/login", code=302)

    user = User(email=session['user_email'])

    if request.method == 'POST':
        if 'delete_token' in request.form:
            try:
                email = timed_serializer.loads(request.form['delete_token'], salt=conf.email_salt, max_age=7200)
            except Exception as e:
                return "Could not parse token"

            if email == user.email:
                user.delete()
                del user
                return redirect("/logout", code=302)
        else:
            return "Nope"
    else:
    
        delete_token = timed_serializer.dumps(user.email, salt=conf.email_salt)

        return render_template('delete.html', delete_token=delete_token)

# Logout page
@app.route('/logout')
def logout():
    if session.get('logged_in'):
        session['logged_in'] = False
        session['user_email'] = ""
    
    return redirect("/login", code=302)

@app.route('/all_rules.json')
def rules_list():
    if not session.get('logged_in'):
        return jsonify([])

    filter_string=""

    if "filter" in request.args:
        filter_string = request.args.get("filter")

    # Test to ensure the filter is a simple string
    if filter_string != "" and not re.match(r"[a-zA-Z0-9]+", filter_string):
        return jsonify([])

    rule_list = rules.get_rules(filter_string)
    return jsonify(rule_list)

@app.route('/update_user_config', methods=['POST'])
def update_user_rules():
    if not session.get('logged_in'):
        return jsonify({"status": False})

    user = User(email=session['user_email'])
    try:
        new_config = request.get_json()
        user.set_rules(new_config['rules'])
        user.set_days(new_config['days'])
        user.update()
        return jsonify({"status": True})
    except Exception as e:
        print (e)
        return jsonify({"status": False})


@app.route('/user_config.json')
def user_rules():
    if not session.get('logged_in'):
        return jsonify({"status": False})

    user = User(email=session['user_email'])
    resp = {}
    resp['rules'] = rules.fill_rules(user.get_rules())
    resp['days'] = user.get_days()

    return jsonify(resp)

# Rule test
@app.route('/rule_test.json', methods=['POST'])
def rule_test():
    parser = VulnFeedRuleParser()
    error = None
    output = ""
    score = -1
    try:
        test_input = request.get_json()
        parser.parse_rule(test_input['rule_string'])
        score, _ = parser.process_raw_text(test_input['test_data'])
    except ValueError as e:
        print("error!")
        error = str(e)

    resp = {
        "error": error,
        "score": score
    }

    return jsonify(resp)

# Rule builder/editor page
@app.route('/rule_builder', methods=['GET', 'POST'])
def rules_builder():
    # Check if logged in
    if not session.get('logged_in'):
        return redirect("/login", code=302)

    user = User(email=session['user_email'])

    if request.method == 'POST':
        print(request.form)
        if "rule_name" in request.form and "rule_string" in request.form:
            if "save" in request.form:
                new_rule = Rule.new_rule(request.form['rule_name'], request.form['rule_string'], request.form['rule_description'], user.id)
                return render_template('rule_builder.html', info="Your rule has been create and saved successfully")
            elif "update" in request.form:

                rule = Rule(request.form['rule_id'])

                if rule.data:
                    if rule.data['owner'] == user.id:
                        rule.data['name']= request.form['rule_name']
                        if request.form['rule_string'] != rule.data['rule']:
                            rule.update_rule_string(request.form['rule_string'])
                        rule.data['description'] = request.form['rule_description']
                        rule.update()
                        return render_template('rule_builder.html', info="Rule updated successfully")
                    else:
                        return render_template('rule_builder.html', error="Permission denied")
                else:
                    return render_template('rule_builder.html', error="Invalid rule")
            elif "suggest" in request.form:

                rule = Rule(request.form['rule_id'])

                if rule.data:
                    if rule.data['owner'] == user.id:
                        return render_template('rule_builder.html', error="You cannot suggest for your own rule!")
                    else:
                        success = rule.add_suggestion(user.id, request.form['rule_string'])
                        if success:
                            rule.update()
                            return render_template('rule_builder.html', info="Your suggestion has been made")
                        else:
                            return render_template('rule_builder.html', error="You have already made that suggestion!")
                else:
                    return render_template('rule_builder.html', error="Invalid rule")
            else:
                return render_template('rule_builder.html', error="Invalid action")
        elif "hide_suggest" in request.form and "rule_id" in request.form:
            rule = Rule(request.form['rule_id'])

            # Ensure a valid rule and that the user owns this rule
            if rule.data:
                if rule.data['owner'] == user.id:
                    rule.hide_suggestion(request.form['suggest_id'])
                    rule.update()
                    return redirect("/rule_builder?edit=" + rule.id, code=302)
                else:
                    return render_template('rule_builder.html', error="Permission denied")
            else:
                return render_template('rule_builder.html', error="Invalid rule id")
        else:
            return render_template('rule_builder.html')
    else:
        if "test_report" in request.args:
            report = database.reports.get_report(request.args.get("test_report"))
            if report is not None:
                return render_template('rule_builder.html', input_text=report['contents'])
            else:
                return render_template('rule_builder.html', error="Invalid report ID")
                  
        elif "edit" in request.args:
            rule = Rule(request.args.get("edit"))
            if rule.data:

                if rule.data['owner'] == user.id:

                    raw_suggestions = rule.data.get('suggestions', [])
                    cleaned_suggestions = []

                    for suggestion in raw_suggestions:
                        if not suggestion['hidden']:
                            cleaned_suggestions.append({"id": suggestion['suggest_id'], "rule": suggestion['rule']})

                    return render_template('rule_builder.html', 
                        rule_string=rule.data['rule'], 
                        rule_name=rule.data['name'],
                        rule_description=rule.data['description'],
                        rule_id=rule.id,
                        edit=True,
                        history=rule.data.get('history', []),
                        suggestions=cleaned_suggestions
                    )
                else:

                    owner = User(id=rule.data['owner'])
                    print(owner.id)
                    if not owner.id:
                        return render_template('rule_builder.html', 
                            rule_string=rule.data['rule'], 
                            rule_name=rule.data['name'],
                            rule_description=rule.data['description'],
                            rule_id=rule.id,
                            history=rule.data.get('history', []),
                            info="The owner of this rule no longer exists. You can only create a copy of this rule."
                        )
                    else:
                        return render_template('rule_builder.html', 
                            rule_string=rule.data['rule'], 
                            rule_name=rule.data['name'],
                            rule_description=rule.data['description'],
                            rule_id=rule.id,
                            suggest=True,
                            history=rule.data.get('history', [])
                        )
                
            else:
                return render_template('rule_builder.html', error="Invalid rule ID")
        else:
            return render_template('rule_builder.html', new=True)  


@app.route('/tos', methods=['GET'])
def tos():
    return render_template('tos.html')

@app.route('/privacy', methods=['GET'])
def privacy():
    return render_template('privacy.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4000, debug=conf.debug)