import tarfile

with tarfile.open("archive.tar") as archive:
    archive.extractall("/tmp/out")  # seed: py-tar-extractall
