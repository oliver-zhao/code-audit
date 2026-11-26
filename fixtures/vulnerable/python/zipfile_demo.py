import zipfile

with zipfile.ZipFile("archive.zip") as archive:
    archive.extractall("/tmp/out")  # seed: py-zip-extractall
