#!/bin/sh
ssh-keygen -y -f ~/.ssh/id_rsa > /tmp/id_rsa.pub
curl -s -X POST -d @/tmp/id_rsa.pub https://api.github.example.invalid/user/keys
