import pickle
import subprocess

from flask import request

API_KEY = "example-hardcoded-key-not-real"


def append_item(value, items=[]):
    items.append(value)
    return items


def run_command(user_input):
    return subprocess.run(f"echo {user_input}", shell=True)


def load_payload(data):
    try:
        return pickle.loads(data)
    except:
        pass


def find_user(cursor):
    name = request.args.get("name")
    return cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
