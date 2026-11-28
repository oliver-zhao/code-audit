#!/bin/sh
age -d -i ~/.ssh/id_ed25519 secrets.env.age > .env
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
