import tarfile


def unpack(path):
    tarfile.open(path).extractall("/tmp/data")
