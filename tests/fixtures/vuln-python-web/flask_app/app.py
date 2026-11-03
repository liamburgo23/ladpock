import pickle

import yaml
from flask import Flask, jsonify, render_template_string, request, send_file
from flask_login import current_user, login_required
from lxml import etree
from openai import OpenAI

from .models import Note, User, db

app = Flask(__name__)
app.secret_key = "dev-secret-key-123"
client = OpenAI()


@app.route("/api/notes", methods=["POST"])
def create_note():
    note = Note(**request.get_json())
    db.session.add(note)
    db.session.commit()
    return jsonify(id=note.id)


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    db.session.delete(note)
    db.session.commit()
    return "", 204


@app.route("/admin/wipe", methods=["POST"])
@login_required
def wipe_everything():
    assert current_user.is_admin
    Note.query.delete()
    db.session.commit()
    return "", 204


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string(f"<h1>Hello {name}</h1>")


@app.route("/download")
def download():
    return send_file(request.args.get("path"))


@app.route("/import", methods=["POST"])
def import_data():
    backup = pickle.loads(request.data)
    settings = yaml.load(request.form["settings"])
    feed = etree.fromstring(request.files["feed"].read(), etree.XMLParser(resolve_entities=True))
    return jsonify(items=len(backup), settings=settings, feed=feed.tag)


@app.route("/api/ask", methods=["POST"])
def ask():
    reply = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": request.json["q"]}])
    return jsonify(reply=reply.choices[0].message.content)


@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if user is None:
        return "User not found", 404
    if user.password != request.form["password"]:
        return "Wrong password", 401
    return jsonify(ok=True)
