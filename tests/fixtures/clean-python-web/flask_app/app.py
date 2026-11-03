import os

from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_login import current_user, login_required
from marshmallow import Schema, fields

from .models import Note, User, db

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
limiter = Limiter(app=app, key_func=lambda: request.remote_addr)


class NoteSchema(Schema):
    text = fields.Str(required=True)


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)


@app.route("/api/notes", methods=["POST"])
@login_required
def create_note():
    data = NoteSchema().load(request.get_json())
    note = Note(text=data["text"], user_id=current_user.id)
    db.session.add(note)
    db.session.commit()
    return jsonify(id=note.id)


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    db.session.delete(note)
    db.session.commit()
    return "", 204


@app.route("/files/<name>")
@login_required
def download(name):
    return send_from_directory(app.config["UPLOAD_DIR"], name)


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginSchema().load(request.form)
    user = User.query.filter_by(email=form["email"]).first()
    if user is None or not user.check_password(form["password"]):
        return "Email or password is incorrect", 401
    return jsonify(ok=True)
