import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # EXPECT command-injection direct
    return "ok"


@app.route("/safe")
def safe():
    os.system("uptime")
    return "ok"
