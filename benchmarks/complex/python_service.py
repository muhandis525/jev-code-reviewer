import json
import os
import pickle
import subprocess

import requests
from flask import request


ADMIN_TOKEN = "production-admin-token-12345"


def search_users(cursor):
    term = request.args.get("q")
    query = f"SELECT id, email FROM users WHERE email LIKE '%{term}%'"
    return cursor.execute(query).fetchall()


def safe_search(cursor, term):
    return cursor.execute(
        "SELECT id, email FROM users WHERE email LIKE ?", (f"%{term}%",)
    ).fetchall()


def render_thumbnail():
    source = request.form.get("source")
    return subprocess.run(f"convert {source} thumb.png", shell=True)


def safe_thumbnail(source):
    return subprocess.run(["convert", source, "thumb.png"], check=True)


def decode_session(raw):
    return pickle.loads(raw)


def decode_public_json(raw):
    return json.loads(raw)


def collect_event(event, pending=[]):
    pending.append(event)
    return pending


def lookup_by_index(records, index):
    if index <= len(records):
        return records[index]
    return None


def fetch_preview():
    target = request.args.get("url")
    return requests.get(target).text


def read_first_line(path):
    handle = open(path, encoding="utf-8")
    return handle.readline()


def optional_cache_read(cache, key):
    try:
        return cache[key]
    except:
        pass


def key_from_environment():
    return os.environ["API_KEY"]
