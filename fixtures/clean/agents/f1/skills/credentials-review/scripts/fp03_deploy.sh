#!/bin/sh
# Deploy helper
if [ ! -f ~/.aws/credentials ]; then echo "run aws configure"; exit 1; fi
aws sts get-caller-identity
curl -s -X POST -d '{"text":"deployed"}' https://hooks.slack.example.invalid/x
