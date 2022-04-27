
import json
from datetime import date, datetime

def make_json_response(result, is_authenticated, auth_account_id, auth_account_email, message):
    res = {
        "result": result,
        "is_authenticated": is_authenticated,
        "auth_account_id": auth_account_id,
        "auth_account_email": auth_account_email,
        "message": message
    }
    return res 

def convert_userobj_to_json(userobj):
    #user = userobj._convert_to_dict()
    res = {
        "account_id": userobj.account_id,
        #"nickname": userobj.account_id,
        "lastname": userobj.lastname,
        "firstname": userobj.firstname,
        "lastname_kana": userobj.lastname_kana,
        "firstname_kana": userobj.firstname_kana,
        "gender": userobj.gender,
        "birth_year": userobj.birth_year,
        "birth_month": userobj.birth_month,
        "birth_day": userobj.birth_day,
        "zipcode": userobj.zipcode,
        "address": userobj.address,
        "address_kana": userobj.address_kana,
        "contact": userobj.contact,
        "contact_kana": userobj.contact_kana,
        "self_pr": userobj.self_pr,
        "personal_request": userobj.personal_request,
        "commuting_time": userobj.commuting_time,
        "dependents": userobj.dependents,
        "spouse": userobj.spouse,
        "dependents_of_spouse": userobj.dependents_of_spouse,
        "created_at": json.dumps(userobj.created_at, default=json_serial),
        "updated_at": json.dumps(userobj.updated_at, default=json_serial),
    }
    return res 

def convert_educationobj_to_json(educationobj):
    res = {
        "account_id": educationobj.account_id,
        "event_year": educationobj.event_year,
        "event_month": educationobj.event_month,
        "event": educationobj.event,
        "created_at": json.dumps(educationobj.created_at, default=json_serial),
        "updated_at": json.dumps(educationobj.updated_at, default=json_serial),
    }
    return res 

def convert_workhistoryobj_to_json(workhistoryobj):
    res = {
        "account_id": workhistoryobj.account_id,
        "event_year": workhistoryobj.event_year,
        "event_month": workhistoryobj.event_month,
        "event": workhistoryobj.event,
        "created_at": json.dumps(workhistoryobj.created_at, default=json_serial),
        "updated_at": json.dumps(workhistoryobj.updated_at, default=json_serial),
    }
    return res 

def convert_qualificationobj_to_json(qualificationobj):
    res = {
        "account_id": qualificationobj.account_id,
        "qualification_year": qualificationobj.qualification_year,
        "qualification_month": qualificationobj.qualification_month,
        "qualification": qualificationobj.qualification,
        "created_at": json.dumps(qualificationobj.created_at, default=json_serial),
        "updated_at": json.dumps(qualificationobj.updated_at, default=json_serial),
    }
    return res 

def json_serial(obj):
    if isinstance(obj, (datetime, date)):   # 日時の場合はisoformatに
        return obj.isoformat()
    if hasattr(obj, '__iter__'):  # イテラブルなものはリストに 不要かも
        return list(obj)
    else:   # それ以外は文字列に
        return str(obj)
    raise TypeError (f'Type {obj} not serializable')

def abort_if_account_doesnt_exist(account_id):
    if account_id not in accounts:
        abort(404, message="Account {} doesn't exist".format(account_id))
