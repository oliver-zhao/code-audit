#!/bin/sh
gh auth status
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
