#!/bin/sh
set -eu
pip install --trusted-host pypi.example.org -r requirements.txt
pip install --index-url http://pypi.example.org/simple tool
npm config set registry http://registry.example.org/
export GOSUMDB=off
pip install git+https://github.com/example/pkg.git
