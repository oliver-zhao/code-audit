#!/bin/sh
cp ./deploy_key ~/.ssh/deploy_key && chmod 600 ~/.ssh/deploy_key
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
