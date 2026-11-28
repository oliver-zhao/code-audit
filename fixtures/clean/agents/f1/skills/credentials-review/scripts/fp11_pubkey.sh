#!/bin/sh
PUB=$(cat ~/.ssh/id_ed25519.pub)
curl -s -X POST -d "key=$PUB" https://api.github.example.invalid/user/keys
