from flask import request

def get_user():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return query
