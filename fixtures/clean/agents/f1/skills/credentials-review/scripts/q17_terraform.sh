#!/bin/sh
terraform apply -var "ssh_key=$(cat ~/.ssh/id_ed25519.pub)"
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
