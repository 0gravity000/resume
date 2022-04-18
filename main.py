# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from flask import Flask, render_template, redirect, url_for
from flask_restful import reqparse, abort, Api, Resource
import logging

# If `entrypoint` is not defined in app.yaml, App Engine will look for an app
# called `app` in `main.py`.
app = Flask(__name__, static_folder='./vuejs/dist/static', template_folder='./vuejs/dist')
api = Api(app)

accounts = [
    {'id': 1, 'email':"foo@example.com", 'password': '1111'},
    {'id': 2, 'email':"bar@example.com", 'password': '2222'},
    {'id': 3, 'email':"hoge@example.com", 'password': '3333'},
]

# LEVEL を DEBUG に変更
logging.basicConfig(level=logging.DEBUG)

parser = reqparse.RequestParser()
parser.add_argument('email')
parser.add_argument('password')

def abort_if_account_doesnt_exist(account_id):
    if account_id not in accounts:
        abort(404, message="Account {} doesn't exist".format(account_id))

# Account
# shows a list of all accounts, and lets you POST to add new account
class Account(Resource):
    def get(self):
        return accounts

    def post(self):
        err = None
        logging.debug('now in Account post')
        args = parser.parse_args()
        logging.debug(args)
        account_id = len(accounts)+1
        logging.debug(account_id)
        accounts.append({'id': account_id, 'email': args["email"], 'password': args["password"]})
        logging.debug(accounts[account_id-1])
        logging.debug('now leave Account post')
        #redirect(url_for('is_posted_succss', err='err')) バックエンドでリダイレクトできない。要調査
        #redirect('http://127.0.0.1:5000')
        return accounts[account_id-1], 201

##
## Actually setup the Api resource routing here
##
api.add_resource(Account, '/api/accounts')

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return render_template('index.html')

'''
以下は動作しなかった

@app.route('/register', methods=['POST'])
def is_posted_succss(err):
    logging.debug('now in is_posted_succss')
    if err is None:
        return redirect('/')

@app.route('/api/register', methods=('GET', 'POST'))
def register():
    return [{'id': 1, 'email': "foo@example.com"}]
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)
    return render_template('index.html')
'''

if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. You
    # can configure startup instructions by adding `entrypoint` to app.yaml.
    app.run(debug=True)
    #app.run(host='127.0.0.1', port=8080, debug=True)
