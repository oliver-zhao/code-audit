#!/bin/sh
docker --config ~/.docker push ghcr.io/o/img:1
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
