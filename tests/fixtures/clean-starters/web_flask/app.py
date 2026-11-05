import os

from flask import Flask, request
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.post("/upload")
@login_required
def upload():
    upload = request.files["file"]
    upload.save(os.path.join("/var/data", f"{current_user.id}-{secure_filename(upload.filename)}"))
    return {"ok": True}
