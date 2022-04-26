from datastore_entity import DatastoreEntity, EntityValue
from flask_login import UserMixin
from datetime import date, datetime
from google.cloud import ndb


'''
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
        """
        UserMixinを継承 メソッド get_id()
        このメソッドは、このユーザーを一意に識別するstrを返す必要があり、
        user_loaderコールバックからユーザーをロードするために使用できます。
        これはstrでなければならないことに注意してください。
        IDがネイティブにintまたはその他の型である場合は、strに変換する必要があります。
        https://flask-login.readthedocs.io/en/latest/_modules/flask_login/mixins/#UserMixin
        """
        return (self.email)
        #return (str(self.key.id))

class User(DatastoreEntity, UserMixin):
    account_id = EntityValue(None)
    nickname = EntityValue(None)
    lastname = EntityValue(None)
    firstname = EntityValue(None)
    lastname_kana = EntityValue(None)
    firstname_kana = EntityValue(None)
    gender = EntityValue(None)
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

    __kind__ = "Users"

    def get_id(self):
        return (self.account_id)

class Education(DatastoreEntity, UserMixin):
    account_id = EntityValue(None)
    event_year = EntityValue(None)
    event_month = EntityValue(None)
    event = EntityValue(None)
    created_at = EntityValue(datetime.utcnow())
    updated_at = EntityValue(datetime.utcnow())

    def get_id(self):
        return (self.account_id)

class Workhistory(DatastoreEntity, UserMixin):
    account_id = EntityValue(None)
    event_year = EntityValue(None)
    event_month = EntityValue(None)
    event = EntityValue(None)
    created_at = EntityValue(datetime.utcnow())
    updated_at = EntityValue(datetime.utcnow())

    def get_id(self):
        return (self.account_id)

class Qualification(DatastoreEntity, UserMixin):
    account_id = EntityValue(None)
    qualification_year = EntityValue(None)
    qualification_month = EntityValue(None)
    qualification = EntityValue(None)
    created_at = EntityValue(datetime.utcnow())
    updated_at = EntityValue(datetime.utcnow())

    def get_id(self):
        return (self.account_id)
'''
# google.cloud.ndb Model ###############################
class Accounts(ndb.Model, UserMixin):
    email = ndb.StringProperty()
    password = ndb.StringProperty()
    created_at = ndb.DateTimeProperty()
    updated_at = ndb.DateTimeProperty()

    def get_id(self):
        """
        UserMixinを継承 メソッド get_id()
        このメソッドは、このユーザーを一意に識別するstrを返す必要があり、
        user_loaderコールバックからユーザーをロードするために使用できます。
        これはstrでなければならないことに注意してください。
        IDがネイティブにintまたはその他の型である場合は、strに変換する必要があります。
        https://flask-login.readthedocs.io/en/latest/_modules/flask_login/mixins/#UserMixin
        """
        return (self.email)
        #return (str(self.key.id))

class Users(ndb.Model, UserMixin):
    account_id = ndb.StringProperty()
    nickname = ndb.StringProperty()
    lastname = ndb.StringProperty()
    firstname = ndb.StringProperty()
    lastname_kana = ndb.StringProperty()
    firstname_kana = ndb.StringProperty()
    gender = ndb.IntegerProperty()
    birth_year = ndb.IntegerProperty()
    birth_month = ndb.IntegerProperty()
    birth_day = ndb.IntegerProperty()
    zipcode = ndb.IntegerProperty()
    address = ndb.StringProperty()
    address_kana = ndb.StringProperty()
    contact = ndb.StringProperty()
    contact_kana = ndb.StringProperty()
    self_pr = ndb.StringProperty()
    personal_request = ndb.StringProperty()
    commuting_time = ndb.StringProperty()
    dependents = ndb.IntegerProperty()
    spouse = ndb.BooleanProperty()
    dependents_of_spouse = ndb.BooleanProperty()
    created_at = ndb.DateTimeProperty()
    updated_at = ndb.DateTimeProperty()

    def get_id(self):
        return (self.account_id)

class Educations(ndb.Model, UserMixin):
    account_id = ndb.StringProperty()
    event_year = ndb.IntegerProperty()
    event_month = ndb.IntegerProperty()
    event = ndb.StringProperty()
    created_at = ndb.DateTimeProperty()
    updated_at = ndb.DateTimeProperty()

    def get_id(self):
        return (self.account_id)

class Workhistories(ndb.Model, UserMixin):
    account_id = ndb.StringProperty()
    event_year = ndb.IntegerProperty()
    event_month = ndb.IntegerProperty()
    event = ndb.StringProperty()
    created_at = ndb.DateTimeProperty()
    updated_at = ndb.DateTimeProperty()

    def get_id(self):
        return (self.account_id)

class Qualifications(ndb.Model, UserMixin):
    account_id = ndb.StringProperty()
    qualification_year = ndb.IntegerProperty()
    qualification_month = ndb.IntegerProperty()
    qualification = ndb.StringProperty()
    created_at = ndb.DateTimeProperty()
    updated_at = ndb.DateTimeProperty()

    def get_id(self):
        return (self.account_id)
