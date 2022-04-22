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

from flask import Flask, render_template, redirect, url_for, session
from flask_restful import reqparse, abort, Api, Resource
import logging
#from google.appengine.ext import ndb   これは2.x系 3.x系は使えない
from google.cloud import datastore
import json
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from datastore_entity import DatastoreEntity, EntityValue
import secrets

# If `entrypoint` is not defined in app.yaml, App Engine will look for an app
# called `app` in `main.py`.
app = Flask(__name__, static_folder='./vuejs/dist/static', template_folder='./vuejs/dist')
#app = Flask(__name__, static_folder='./vuejs/dist/static', static_url_path='/vuejs/dist/static')
api = Api(app)  #flask_restful
login_manager = LoginManager()  #flask_login
login_manager.init_app(app) #flask_login
secret = secrets.token_urlsafe(32)  #flask_login ランダムなセッションを生成
app.secret_key = secret

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
#parser.add_argument('nickname')

def abort_if_account_doesnt_exist(account_id):
    if account_id not in accounts:
        abort(404, message="Account {} doesn't exist".format(account_id))

# flask_restful
# Account
# shows a list of all accounts, and lets you POST to add new account
class RegisterRestful(Resource):
    def get(self):  
        pass
        '''
        #デバッグ用 本番は動作させない
        accounts = fetch_all_account()
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

# flask_restful
# Login
class LoginRestful(Resource):
    def post(self):
        err = None
        logging.debug('now in Login post')
        args = parser.parse_args()
        logging.debug(args)
        #email = args["email"]
        #hashed_password=generate_password_hash(args["password"], method='sha256')
        #logging.debug(hashed_password)
        #remember = True if request.form.get('remember') else False

        user = Account().get_obj('email',args["email"])
        #user = Account.fetch_account(args["email"])
        logging.debug(user)
        #logging.debug(user[0]["email"])

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, args["password"]):
        #if not user or not check_password_hash(user[0]["password"], args["password"]):
            # flash('Please check your login details and try again.')   #どうやるか要調査
            logging.debug('now leave Login post: auth NG')
            return user.email, 401
            #return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

        # if the above check passes, then we know the user has the right credentials
        # login_userにuserを渡すと、後は必要なことはflask-loginがやってくれます。
        # 主にログイン状態の保持に必要な情報をセッションに保存しているのと、
        # リクエストコンテキストのuserのアップデート、ログインシグナルの送信などをしてくれています
        login_user(user)
        logging.debug('now leave Login post: auth OK')
        return user.email, 201
        #return redirect(url_for('main.profile'))

class LogoutRestful(Resource):
    def get(self):
        err = None
        logging.debug('now in Logout get')
        logout_user()
        logging.debug('now leave Logout get')
        #return redirect('TopView')
        return "LogoutRestful"

class TopRestful(Resource):
    def get(self):
        logging.debug('now in top get')
        logging.debug('now leave top get')
        return "TopRestful"
      
##
## Actually setup the Api resource routing here
##
api.add_resource(RegisterRestful, '/api/register')
api.add_resource(LoginRestful, '/api/login')
api.add_resource(LogoutRestful, '/api/logout')
api.add_resource(TopRestful, '/api/top')

# Cloud Datastore ################################
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

def fetch_all_account():
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

# Flask-login Model ###############################
class Account(DatastoreEntity, UserMixin):
    id = EntityValue(None)
    email = EntityValue(None)
    password = EntityValue(None)
    #user_id = EntityValue(None)
    created_at = EntityValue(None)
    updated_at = EntityValue(None)
    #date_created = EntityValue(datetime.datetime.utcnow())
    # specify the name of the entity kind.
    # This is REQUIRED. Raises ValueError otherwise
    __kind__ = "Accounts"

    """
    UserMixinを継承 メソッド get_id()
    このメソッドは、このユーザーを一意に識別するstrを返す必要があり、
    user_loaderコールバックからユーザーをロードするために使用できます。
    これはstrでなければならないことに注意してください。
    IDがネイティブにintまたはその他の型である場合は、strに変換する必要があります。
    https://flask-login.readthedocs.io/en/latest/_modules/flask_login/mixins/#UserMixin
    """

    def fetch_account(email):
        query = datastore_client.query(kind='Accounts')
        query.add_filter("email", "=", email)
        query.order = ['-updated_at']
        account = list(query.fetch())
        #logging.debug(account)
        #logging.debug(account[0]["email"])
        return account

class User(UserMixin):
    pass

# Flask-login ###############################
# user_loaderコールバックを提供する必要があります。 
# このコールバックは、セッションに保存されているユーザーIDからユーザーオブジェクトをリロードするために使用されます。 
# ユーザーのstr IDを取得し、対応するユーザーオブジェクトを返す必要があります。
@login_manager.user_loader
def load_user(account_id):  #userをロードするためのcallback functionを定義
    #load_userの引数は、Userクラスで定義したget_id()が返す値です。
    account = Account().get_obj('id', account_id)
    return account

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=('GET', 'POST'))
def index(path):
    return render_template('index.html')

'''   
# router キャッチオールエンドポイント
# https://flask.palletsprojects.com/en/2.1.x/patterns/singlepageapplications/
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return app.send_static_file("index.html")
'''

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
