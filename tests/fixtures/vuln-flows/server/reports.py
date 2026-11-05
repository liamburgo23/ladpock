import os
import subprocess

import requests
from flask import Blueprint, redirect, render_template_string, request

bp = Blueprint("reports", __name__)


@bp.get("/reports/search")
def search():
    term = request.args.get("term")
    query = f"SELECT * FROM reports WHERE title = '{term}'"
    return db.execute(query).fetchall()


@bp.post("/reports/export")
def export():
    fmt = request.json["format"]
    cmd = "pandoc report.md -t " + fmt
    return subprocess.check_output(cmd, shell=True)


@bp.get("/reports/file")
def read_file():
    name = request.args["name"]
    path = os.path.join("/srv/reports", name)
    return open(path).read()


@bp.post("/reports/fetch")
def fetch_remote():
    target = request.json["url"]
    return requests.get(target).text


@bp.get("/reports/back")
def back():
    next_url = request.args.get("next")
    return redirect(next_url)


@bp.get("/reports/render")
def render():
    text = request.args.get("t")
    return render_template_string(text)
