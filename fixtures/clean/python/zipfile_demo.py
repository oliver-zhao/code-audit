import zipfile

with zipfile.ZipFile("archive.zip") as archive:
    for member in archive.namelist():
        if member.startswith("/") or ".." in member:
            continue
        archive.extract(member, "/tmp/out")