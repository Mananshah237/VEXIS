import os
from flask import session

def admin_welcome():
    user = session["user"]
    os.system(f"echo Welcome {user}")
    return "ok"
