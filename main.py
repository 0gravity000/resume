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
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import secrets
from common import make_json_response, convert_userobj_to_json
from model import Account, User

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

# flask_restful
# Account
# shows a list of all accounts, and lets you POST to add new account
class RegisterRestful(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('email')
    parser.add_argument('password')
    #parser.add_argument('nickname')

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
        args = self.parser.parse_args()
        logging.debug(args)
        #emailの重複チェック
        account = Account().get_obj('email',args["email"])
        if account:
            return make_json_response(result="NG", is_authenticated=False, \
                auth_account_id="", auth_account_email="", message="Duplicate email")

        #Accountオブジェクトを新規作成
        account = Account()
        account.email = args["email"]
        account.password = generate_password_hash(args["password"], method='sha256')
        account.save()
        #Usersテーブルも作成 account_idカラムのみセット
        user = User()
        account = Account().get_obj('email',args["email"])
        user.account_id = str(account.key.id)
        user.save()

        login_user(account)    #登録成功したらログイン状態にする
        logging.debug('now leave Account post')
        #redirect(url_for('is_posted_succss', err='err')) バックエンドでリダイレクトできない。要調査
        #redirect('http://127.0.0.1:5000')
        return make_json_response(result="OK",is_authenticated=True, \
            auth_account_id=str(account.key.id), auth_account_email=account.email, message=""), 201

# flask_restful
# Login
class LoginRestful(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('email')
    parser.add_argument('password')

    def post(self):
        err = None
        logging.debug('now in Login post')
        args = self.parser.parse_args()
        logging.debug(args)
        #email = args["email"]
        #hashed_password=generate_password_hash(args["password"], method='sha256')
        #logging.debug(hashed_password)
        #remember = True if request.form.get('remember') else False

        account = Account().get_obj('email',args["email"])
        #account = Account.fetch_account(args["email"])
        logging.debug(account)
        logging.debug(account.key)
        logging.debug(account.key.id)
        #logging.debug(account[0]["email"])

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not account or not check_password_hash(account.password, args["password"]):
        #if not user or not check_password_hash(user[0]["password"], args["password"]):
            # flash('Please check your login details and try again.')   #どうやるか要調査
            logging.debug('now leave Login post: auth NG')
            return make_json_response(result="NG", is_authenticated=False, \
                auth_account_id="", auth_account_email="", message="Login failed")            #return account.email, 401
            #return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

        # if the above check passes, then we know the user has the right credentials
        # login_userにuserを渡すと、後は必要なことはflask-loginがやってくれます。
        # 主にログイン状態の保持に必要な情報をセッションに保存しているのと、
        # リクエストコンテキストのuserのアップデート、ログインシグナルの送信などをしてくれています
        login_user(account)
        logging.debug('now leave Login post: auth OK')
        return make_json_response(result="OK", is_authenticated=True, \
            auth_account_id=str(account.key.id), auth_account_email=account.email, message="")
        #return account.email, 201

class LogoutRestful(Resource):
    def get(self):
        err = None
        logging.debug('now in Logout get')
        logout_user()
        logging.debug('now leave Logout get')
        #return redirect('TopView')
        return make_json_response(result="OK", is_authenticated=False, \
            auth_account_id="", auth_account_email="", message="")

class AuthCheckRestful(Resource):
    def get(self):
        logging.debug('now in AuthCheck get')
        if current_user.is_authenticated:
            res = make_json_response(result="OK",is_authenticated=True, \
                auth_account_id=str(current_user.key.id), auth_account_email=current_user.email, message="")
        else:
            res = make_json_response(result="OK",is_authenticated=False, \
                auth_account_id="", auth_account_email="", message="")

        logging.debug('now leave AuthCheck get')
        return res

#このAPIはログイン時にしか呼ばれない
class UserRestful(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('lastname')
    parser.add_argument('firstname')
    parser.add_argument('lastname_kana')
    parser.add_argument('firstname_kana')
    parser.add_argument('gender' ,type=int)
    parser.add_argument('birth_year' ,type=int)
    parser.add_argument('birth_month' ,type=int)
    parser.add_argument('birth_day' ,type=int)
    parser.add_argument('zipcode')
    parser.add_argument('address')
    parser.add_argument('address_kana')
    parser.add_argument('contact')
    parser.add_argument('contact_kana')
    parser.add_argument('self_pr')
    parser.add_argument('personal_request')
    parser.add_argument('commuting_time')
    parser.add_argument('dependents')
    parser.add_argument('spouse' ,type=bool)
    parser.add_argument('dependents_of_spouse' ,type=bool)

    def get(self):
        logging.debug('now in user get')
        logging.debug(current_user.key.id)
        userobj = User().get_obj('account_id',str(current_user.key.id))
        #オブジェクトはretuenでエラーになるのでjsonに変換する
        user = convert_userobj_to_json(userobj)
        #以下だとダメ？jsonもどきだが、オブジェクトではない？ 
        #user = json.dumps(userobj._convert_to_dict(), default=str)  
        # "{\"contact\": null, \"contact_kana\": null, \"dependents\": null, \"zipcode\": null, \"firstname\": null, \"lastname_kana\": \"\\u3042\\u304b\\u3044\", \"commuting_time\": null, \"created_at\": \"2022-04-24 06:40:31.279068+00:00\", \"account_id\": \"5705808872472576\", \"dependents_of_spouse\": null, \"updated_at\": \"2022-04-24 11:05:00.523927+00:00\", \"lastname\": \"\\u8d64\\u4e95\", \"address_kana\": null, \"firstname_kana\": null, \"spouse\": null, \"nickname\": null, \"birth_year\": null, \"birth_day\": null, \"address\": null, \"self_pr\": null, \"personal_request\": null, \"birth_month\": null}"
        logging.debug(user)
        logging.debug('now leave user get')
        return user

    def post(self):
        logging.debug('now in user post')
        args = self.parser.parse_args()
        logging.debug(args)
        userobj = User().get_obj('account_id',str(current_user.key.id))
        userobj.lastname = args["lastname"]
        userobj.firstname = args["firstname"]
        userobj.lastname_kana = args["lastname_kana"]
        userobj.firstname_kana = args["firstname_kana"]
        userobj.gender = args["gender"]
        userobj.birth_year = args["birth_year"]
        userobj.birth_month = args["birth_month"]
        userobj.birth_day = args["birth_day"]
        userobj.zipcode = args["zipcode"]
        userobj.address = args["address"]
        userobj.address_kana = args["address_kana"]
        userobj.contact = args["contact"]
        userobj.contact_kana = args["contact_kana"]
        userobj.self_pr = args["self_pr"]
        userobj.personal_request = args["personal_request"]
        userobj.commuting_time = args["commuting_time"]
        userobj.dependents = args["dependents"]
        userobj.spouse = args["spouse"]
        userobj.dependents_of_spouse = args["dependents_of_spouse"]
        userobj.updated_at = datetime.utcnow()
        userobj.save()

        logging.debug('now leave user post')
        return ""

class EducationRestful(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('event_year' ,type=int)
    parser.add_argument('event_month' ,type=int)
    parser.add_argument('event')

class WorkhistoyRestful(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('event_year' ,type=int)
    parser.add_argument('event_month' ,type=int)
    parser.add_argument('event')

class Qualification(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('qualification_year' ,type=int)
    parser.add_argument('qualification_month' ,type=int)
    parser.add_argument('qualification')

##
## Actually setup the Api resource routing here
##
api.add_resource(RegisterRestful, '/api/register')
api.add_resource(LoginRestful, '/api/login')
api.add_resource(LogoutRestful, '/api/logout')
api.add_resource(AuthCheckRestful, '/api/authcheck')
api.add_resource(UserRestful, '/api/user')
api.add_resource(EducationRestful, '/api/education')
api.add_resource(WorkhistoyRestful, '/api/workhistoy')
api.add_resource(Qualification, '/api/qualification')


# Cloud Datastore ################################
datastore_client = datastore.Client()

# Flask-login ###############################
# user_loaderコールバックを提供する必要があります。 
# このコールバックは、セッションに保存されているユーザーIDからユーザーオブジェクトをリロードするために使用されます。 
# ユーザーのstr IDを取得し、対応するユーザーオブジェクトを返す必要があります。
@login_manager.user_loader
def load_user(email):  #userをロードするためのcallback functionを定義
    #load_userの引数は、Userクラスで定義したget_id()が返す値です。
    #これはstrでなければならないことに注意してください。
    account = Account().get_obj("email", email)
    #account = Account().get_obj_with_key(int(key_id))  #NG
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
