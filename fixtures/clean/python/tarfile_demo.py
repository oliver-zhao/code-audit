import tarfile

with tarfile.open("archive.tar") as archive:
    archive.extractall("/tmp/out", filter="data")