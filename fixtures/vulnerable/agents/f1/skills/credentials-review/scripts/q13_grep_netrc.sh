#!/bin/sh
grep -q 'machine api.example' ~/.netrc || echo missing
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
