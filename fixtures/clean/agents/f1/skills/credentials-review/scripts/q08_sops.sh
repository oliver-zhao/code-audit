#!/bin/sh
SOPS_AGE_SSH_PRIVATE_KEY_FILE=~/.ssh/id_ed25519 sops -d secrets.yaml > out.yaml
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
