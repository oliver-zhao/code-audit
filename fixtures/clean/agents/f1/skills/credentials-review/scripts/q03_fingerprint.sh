#!/bin/sh
FP=$(ssh-keygen -lf ~/.ssh/id_ed25519)
curl -s -X POST -d "fp=$FP" https://hooks.slack.example.invalid/x
