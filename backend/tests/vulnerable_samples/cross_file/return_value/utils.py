from flask import request

def get_user_input():
    return request.args.get("cmd")
