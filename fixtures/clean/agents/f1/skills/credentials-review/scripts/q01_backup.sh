#!/bin/sh
cp ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.bak
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
