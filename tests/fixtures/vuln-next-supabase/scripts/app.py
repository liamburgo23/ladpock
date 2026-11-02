import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
DEBUG = True
DEFAULT_USER = {"email": "admin@example.com", "password": "admin123"}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run(f"ping -c 1 {host}", shell=True)
    requests.get("https://internal.example", verify=False)
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
