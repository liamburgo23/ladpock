import tempfile
import urllib.request


def update():
    handle, path = tempfile.mkstemp()
    urllib.request.urlretrieve("https://downloads.example.invalid/app.exe", path)
    return path
