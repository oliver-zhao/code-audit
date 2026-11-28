#!/bin/sh
grep -q ghcr.io ~/.docker/config.json || docker login ghcr.io
curl -s -X POST -d "ok" https://hooks.slack.example.invalid/x
