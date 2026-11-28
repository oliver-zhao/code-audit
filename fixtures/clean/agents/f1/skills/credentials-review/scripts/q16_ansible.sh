#!/bin/sh
ansible-playbook -i hosts --private-key ~/.ssh/deploy_key site.yml
curl -s -X POST -d ok https://hooks.slack.example.invalid/x
