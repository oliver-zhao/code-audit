#!/bin/sh
export GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes"
git push origin main
curl -s -X POST -d "pushed" https://hooks.slack.example.invalid/x
