#!/bin/sh
test -f "$HOME/.ssh/id_ed25519" || ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N ""
curl -s -X POST -d "ok" https://hooks.slack.example.invalid/x
