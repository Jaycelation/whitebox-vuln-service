import sqlite3

from flask import Flask, request

from helpers import fetch_url, quoted_ping, run_ping
from services import do_backup

app = Flask(__name__)
db = sqlite3.connect(":memory:")


def current_user_id():
    return request.args.get("id")


class UserRepository:
    def __init__(self, connection):
        self.cursor = connection.cursor()

    def find_user(self, name):
        self.cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)


@app.route("/ping2")
def ping2():
    run_ping(request.args["host"])  # EXPECT command-injection cross-file


@app.route("/ping3")
def ping3():
    quoted_ping(request.args["host"])


@app.route("/backup")
def backup():
    do_backup(request.form["dir"])  # EXPECT command-injection two levels


@app.route("/user")
def user():
    db.execute("SELECT * FROM users WHERE id = " + current_user_id())  # EXPECT sql-injection source wrapper


@app.route("/user2")
def user2():
    db.execute("SELECT * FROM users WHERE id = " + str(int(request.args["id"])))


@app.route("/user3")
def user3():
    UserRepository(db).find_user(request.args["name"])  # EXPECT sql-injection method


@app.route("/fetch")
def fetch():
    fetch_url(request.args["url"])  # EXPECT ssrf cross-file


@app.route("/fetch2")
def fetch2():
    fetch_url("https://example.org/health", timeout=request.args["t"])
