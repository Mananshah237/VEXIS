from flask import request, session

def login():
    username = request.form.get("username")
    password = request.form.get("password")
    # (auth check omitted for brevity)
    session["user"] = username
    return "logged in"
