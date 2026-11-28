#!/bin/sh
git -c gpg.format=ssh -c user.signingkey=~/.ssh/id_ed25519 commit -S -m release
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
