import os


def save(request):
    upload = request.files["file"]
    upload.save(os.path.join("/var/data", upload.filename))
