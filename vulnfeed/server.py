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
        if not re.match(r"[^@$<>;'\"]+@[^@$<>;'\"]+\.[^@$<>;'\"]+", request.form['email']):
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
            
            url = conf.domain + "/verify/" + timed_serializer.dumps(result.email, salt=conf.email_salt)

            render_map = {
                "url": url,
            }
            
            send_email("verify_email.html", "Verification for VulnFeed", render_map, result.email)
            
            if result:
                return redirect("/login", code=302)
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

    user = User(email)

    if user.hash is not None:
        user.set_confirmed()
        user.update()
        return "Your address has been verified. You can now login!"
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
            
            user = User(request.form['email'])

            if user.hash is None:
                return render_template('forgot.html', sitekey=conf.recaptcha_sitekey, server_error="Account not found")

            url = conf.domain + "/resetpass/" + timed_serializer.dumps(user.email, salt=conf.email_salt)

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

    if request.method == 'POST':
        if request.form['password'] != request.form['password2']:
            return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Passwords do not match!")
        else:
            user = User(email)
            user.new_password(request.form['password'])
            user.update()
        return redirect("/login", code=302) 
    else:
        user = User(email)

        if user.hash is not None:
            return render_template('resetpass.html', user_token=token)
        else:
            return "Invalid token"

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():

    if address_failed_login(request.remote_addr):
        return render_template('login.html', server_error="You have exceeded the number of fail logins. Try again later")

    if request.method == 'POST':
        message = ""
        user = User(request.form['email'])

        if user.login(request.form['password']) and user.is_confirmed():
            session['logged_in'] = True
            session['user_email'] = request.form['email']
            clear_failed_login(request.remote_addr)
            return redirect("/", code=302)
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

# Login page
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

    rule_list = rules.get_rules()
    return jsonify(rule_list)

@app.route('/update_user_config', methods=['POST'])
def update_user_rules():
    if not session.get('logged_in'):
        return jsonify({"status": False})

    user = User(session['user_email'])
    # try:
    new_config = request.get_json()
    user.set_rules(new_config['rules'])
    user.set_days(new_config['days'])
    user.update()
    return jsonify({"status": True})
    # except Exception as e:
    #     print (e)
    #     pass


@app.route('/user_config.json')
def user_rules():
    if not session.get('logged_in'):
        return jsonify({"status": False})

    user = User(session['user_email'])
    resp = {}
    resp['rules'] = rules.fill_rules(user.get_rules())
    resp['days'] = user.get_days()

    return jsonify(resp)

# Rule builder page
@app.route('/rule_builder', methods=['GET', 'POST'])
def rules_builder():
    if not session.get('logged_in'):
        return redirect("/login", code=302)

    if request.method == 'POST':
        # Check for test
        if request.form['rule_string'] and "test" in request.form:
            parser = VulnFeedRuleParser()
            error = ""
            output = ""
            score = -1
            try:
                parser.parse_rule(request.form['rule_string'])
                score, _ = parser.process_raw_text(request.form['input_text'])
            except ValueError as e:
                print("error!")
                error = str(e)

            return render_template('rule_builder.html', 
                                   output=score, 
                                   error=error, 
                                   rule_string=request.form['rule_string'], 
                                   rule_name=request.form['rule_name'],
                                   rule_description=request.form['rule_description'],
                                   input_text=request.form['input_text']
                                  )
        elif request.form['rule_name'] and request.form['rule_string'] and "save" in request.form:
            new_rule = Rule.new_rule(request.form['rule_name'], request.form['rule_string'], request.form['rule_description'])
            return render_template('rule_builder.html')
        else:
            return render_template('rule_builder.html')
    else:
        return render_template('rule_builder.html')  

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4000, debug=conf.debug)