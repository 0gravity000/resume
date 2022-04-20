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
#from google.appengine.ext import ndb   これは2.x系 3.x系は使えない
from google.cloud import datastore
import json
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash

# If `entrypoint` is not defined in app.yaml, App Engine will look for an app
# called `app` in `main.py`.
app = Flask(__name__, static_folder='./vuejs/dist/static', template_folder='./vuejs/dist')
api = Api(app)

'''
ダミーアカウント
accounts = [
    {'id': 1, 'email':"foo@example.com", 'password': '1111'},
    {'id': 2, 'email':"bar@example.com", 'password': '2222'},
    {'id': 3, 'email':"hoge@example.com", 'password': '3333'},
]
'''

# LEVEL を DEBUG に変更
logging.basicConfig(level=logging.DEBUG)

parser = reqparse.RequestParser()
parser.add_argument('email')
parser.add_argument('password')

def abort_if_account_doesnt_exist(account_id):
    if account_id not in accounts:
        abort(404, message="Account {} doesn't exist".format(account_id))

# flask_restful
# Account
# shows a list of all accounts, and lets you POST to add new account
class AccountRestful(Resource):
    def get(self):  
        pass
        '''
        #デバッグ用 本番は動作させない
        accounts = fetch_account()
        logging.debug(accounts)
        res = []
        for entity in accounts:
            res.append(
                {
                    "id": entity.key.id,
                    "email": entity["email"],
                    "password": entity["password"],
                    "created_at": entity["created_at"],
                    "updated_at": entity["updated_at"],
                }
            )
        return res
        '''

    def post(self):
        err = None
        logging.debug('now in Account post')
        args = parser.parse_args()
        logging.debug(args)
        account = store_account(
                email=args["email"],
                hashed_password=generate_password_hash(args["password"], method='sha256')
            )
        logging.debug('now leave Account post')
        #redirect(url_for('is_posted_succss', err='err')) バックエンドでリダイレクトできない。要調査
        #redirect('http://127.0.0.1:5000')
        return account, 201

##
## Actually setup the Api resource routing here
##
api.add_resource(AccountRestful, '/api/accounts')

# Cloud Datastore
datastore_client = datastore.Client()

def store_account(email, hashed_password):
    dt_now = datetime.now()
    # print(dt_now)
    entity = datastore.Entity(key=datastore_client.key('Accounts'))
    accountObj = {
        'email': email,
        'password': hashed_password,
        'created_at': json.dumps(dt_now, default=json_serial),
        'updated_at': json.dumps(dt_now, default=json_serial)
        }
    entity.update(accountObj)
    datastore_client.put(entity)
    return accountObj

def fetch_account():
    query = datastore_client.query(kind='Accounts')
    query.order = ['-updated_at']
    accounts = query.fetch()
    return accounts

def json_serial(obj):
    if isinstance(obj, (datetime, date)):   # 日時の場合はisoformatに
        return obj.isoformat()
    if hasattr(obj, '__iter__'):  # イテラブルなものはリストに 不要かも
        return list(obj)
    else:   # それ以外は文字列に
        return str(obj)
    raise TypeError (f'Type {obj} not serializable')



@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return render_template('index.html')

'''
以下は動作しなかった
ルーチィングはvue側で制御する

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
