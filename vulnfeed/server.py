from pymongo import MongoClient
from bson.objectid import ObjectId
import pymongo.errors as mongo_errors

from flask import Flask, flash, redirect, render_template, request, session, abort, jsonify
import os
import json
import re
import requests

from database.user import User
import database.rules as rules
from database.rules import Rule
from scorer.parser import VulnFeedRuleParser

from config import Config

conf = Config()

app = Flask(__name__)

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
                    print(captcha_verify_json)
                    return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Captcha failure")

            # Insert new user
            result =  User.new_user(request.form['email'], request.form['password'])
            
            if result:
                return redirect("/login", code=302)
            else:
                return render_template('signup.html', sitekey=conf.recaptcha_sitekey, server_error="Could not create account. Perhaps an account of that name already exists?")
        
    else:
        return render_template('signup.html', sitekey=conf.recaptcha_sitekey)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        message = ""
        user = User(request.form['email'])
        if user.login(request.form['password']):
            session['logged_in'] = True
            session['user_email'] = request.form['email']
            return redirect("/", code=302)
        else:
            session['logged_in'] = False
            session['user_email'] = ""
            message = "Incorrect user/password"

        return render_template('login.html', server_error=message)
    else:
        return render_template('login.html')

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

@app.route('/rule_builder', methods=['GET', 'POST'])
def rules_builder():
    if not session.get('logged_in'):
        return redirect("/login", code=302)

    if request.method == 'POST':
        if request.form['input_text'] and request.form['rule_string'] and "test" in request.form:
            parser = VulnFeedRuleParser()
            error = ""
            output = ""
            try:
                parser.parse_rule(request.form['rule_string'])
                score, _ = parser.process_raw_text(request.form['input_text'])
            except ValueError as e:
                print("error!")
                error = str(e)

            return render_template('rule_builder.html', output=score, error=error, rule_string=request.form['rule_string'], input_text=request.form['input_text'])
        elif request.form['input_text'] and request.form['rule_string'] and "save" in request.form:
            new_rule = Rule.new_rule(request.form['rule_name'], request.form['rule_string'], request.form['rule_description'])
            return render_template('rule_builder.html')
        else:
            return render_template('rule_builder.html')
    else:
        return render_template('rule_builder.html')  

if __name__ == "__main__":
    app.secret_key = conf.secret
    app.run(host='0.0.0.0', port=4000, debug=conf.debug)