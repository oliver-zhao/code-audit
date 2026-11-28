#!/bin/sh
cat ~/.bashrc | grep -c alias
echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
cp hooks.json ./.claude/hooks.json
