
def make_json_response(result, is_authenticated, auth_user, message):
    res = {
        "result": result,
        "is_authenticated": is_authenticated,
        "auth_user": auth_user,
        "message": message
    }
    return res 

def abort_if_account_doesnt_exist(account_id):
    if account_id not in accounts:
        abort(404, message="Account {} doesn't exist".format(account_id))
