import os
import subprocess

import requests
from flask import Blueprint, abort, redirect, render_template, request
from werkzeug.utils import secure_filename

bp = Blueprint("reports", __name__)
FORMATS = {"pdf", "html"}


@bp.get("/reports/search")
def search():
    term = request.args.get("term")
    return db.execute("SELECT id, title FROM reports WHERE title = %s LIMIT 50", (term,)).fetchall()


@bp.post("/reports/export")
def export():
    fmt = request.json["format"]
    if fmt not in FORMATS:
        abort(400)
    return subprocess.check_output(["pandoc", "report.md", "-t", fmt])


@bp.get("/reports/file")
def read_file():
    name = secure_filename(request.args["name"])
    with open(os.path.join("/srv/reports", name)) as handle:
        return handle.read()


@bp.get("/reports/status")
def status():
    item = request.args.get("id")
    return requests.get(f"https://reports.example.invalid/items/{item}", timeout=5).text


@bp.get("/reports/home")
def home():
    name = request.args.get("name")
    return render_template("home.html", name=name)
