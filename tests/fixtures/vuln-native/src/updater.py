import tempfile
import urllib.request


def update():
    path = tempfile.mktemp()
    urllib.request.urlretrieve("http://downloads.example.invalid/app.exe", path)
    return path
