from datastore_entity import DatastoreEntity, EntityValue
from flask_login import UserMixin
from datetime import date, datetime

# Flask-login Model ###############################
class Account(DatastoreEntity, UserMixin):
    #id = EntityValue(None)
    email = EntityValue(None)
    password = EntityValue(None)
    #user_id = EntityValue(None)
    created_at = EntityValue(datetime.utcnow())
    updated_at = EntityValue(datetime.utcnow())
    #date_created = EntityValue(datetime.datetime.utcnow())
    # specify the name of the entity kind.
    # This is REQUIRED. Raises ValueError otherwise
    __kind__ = "Accounts"

    def get_id(self):
        return (self.email)
        #return (str(self.key.id))
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

class User(DatastoreEntity, UserMixin):
    account_id = EntityValue(None)
    nickname = EntityValue(None)
    lastname = EntityValue(None)
    firstname = EntityValue(None)
    lastname_kana = EntityValue(None)
    firstname_kana = EntityValue(None)
    birth_year = EntityValue(None)
    birth_month = EntityValue(None)
    birth_day = EntityValue(None)
    zipcode = EntityValue(None)
    address = EntityValue(None)
    address_kana = EntityValue(None)
    contact = EntityValue(None)
    contact_kana = EntityValue(None)
    self_pr = EntityValue(None)
    personal_request = EntityValue(None)
    commuting_time = EntityValue(None)
    dependents = EntityValue(None)
    spouse = EntityValue(None)
    dependents_of_spouse = EntityValue(None)
    created_at = EntityValue(datetime.utcnow())
    updated_at = EntityValue(datetime.utcnow())

    __kind__ = "Accounts"
