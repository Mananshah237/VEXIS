import subprocess
from utils import get_user_input

def run_command():
    cmd = get_user_input()
    subprocess.run(cmd, shell=True)
    return "done"
