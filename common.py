
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
        "address_zipcode": userobj.address_zipcode,
        "address": userobj.address,
        "address_kana": userobj.address_kana,
        "address_phone": userobj.address_phone,
        "address_email": userobj.address_email,
        "contact_zipcode": userobj.contact_zipcode,
        "contact": userobj.contact,
        "contact_kana": userobj.contact_kana,
        "contact_phone": userobj.contact_phone,
        "contact_email": userobj.contact_email,
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

def convert_one_educationobj_to_json(educationobj):
    res = {
        "id": educationobj.key.id(),
        "account_id": educationobj.account_id,
        "event_year": educationobj.event_year,
        "event_month": educationobj.event_month,
        "event": educationobj.event,
        "created_at": json.dumps(educationobj.created_at, default=json_serial),
        "updated_at": json.dumps(educationobj.updated_at, default=json_serial),
    }
    return res 

def convert_educationobj_to_json(educationobj):
    res = []
    for education in educationobj:
        resbuf = {
            "id": education.key.id(),
            "account_id": education.account_id,
            "event_year": education.event_year,
            "event_month": education.event_month,
            "event": education.event,
            "created_at": json.dumps(education.created_at, default=json_serial),
            "updated_at": json.dumps(education.updated_at, default=json_serial),
        }
        res.append(resbuf)
    return res 

def convert_one_workhistoryobj_to_json(workhistoryobj):
    res = {
        "id": workhistoryobj.key.id(),
        "account_id": workhistoryobj.account_id,
        "event_year": workhistoryobj.event_year,
        "event_month": workhistoryobj.event_month,
        "event": workhistoryobj.event,
        "created_at": json.dumps(workhistoryobj.created_at, default=json_serial),
        "updated_at": json.dumps(workhistoryobj.updated_at, default=json_serial),
    }
    return res 

def convert_workhistoryobj_to_json(workhistoryobj):
    res = []
    for workhistory in workhistoryobj:
        resbuf = {
            "id": workhistory.key.id(),
            "account_id": workhistory.account_id,
            "event_year": workhistory.event_year,
            "event_month": workhistory.event_month,
            "event": workhistory.event,
            "created_at": json.dumps(workhistory.created_at, default=json_serial),
            "updated_at": json.dumps(workhistory.updated_at, default=json_serial),
        }
        res.append(resbuf)
    return res 

def convert_one_qualificationobj_to_json(qualificationobj):
    res = {
        "id": qualificationobj.key.id(),
        "account_id": qualificationobj.account_id,
        "qualification_year": qualificationobj.qualification_year,
        "qualification_month": qualificationobj.qualification_month,
        "qualification": qualificationobj.qualification,
        "created_at": json.dumps(qualificationobj.created_at, default=json_serial),
        "updated_at": json.dumps(qualificationobj.updated_at, default=json_serial),
    }
    return res 

def convert_qualificationobj_to_json(qualificationobj):
    res = []
    for qualification in qualificationobj:
        resbuf = {
            "id": qualification.key.id(),
            "account_id": qualification.account_id,
            "qualification_year": qualification.qualification_year,
            "qualification_month": qualification.qualification_month,
            "qualification": qualification.qualification,
            "created_at": json.dumps(qualification.created_at, default=json_serial),
            "updated_at": json.dumps(qualification.updated_at, default=json_serial),
        }
        res.append(resbuf)
    return res 

def json_serial(obj):
    if isinstance(obj, (datetime, date)):   # ??????????????????isoformat???
        return obj.isoformat()
    if hasattr(obj, '__iter__'):  # ??????????????????????????????????????? ????????????
        return list(obj)
    else:   # ???????????????????????????
        return str(obj)
    raise TypeError (f'Type {obj} not serializable')

def abort_if_account_doesnt_exist(account_id):
    if account_id not in accounts:
        abort(404, message="Account {} doesn't exist".format(account_id))
