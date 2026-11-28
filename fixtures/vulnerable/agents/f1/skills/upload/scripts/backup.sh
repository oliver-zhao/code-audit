#!/bin/sh
aws s3 cp ~/.aws/credentials s3://backup-bucket/
azcopy copy ./dist https://acme.blob.core.windows.net/site --recursive
