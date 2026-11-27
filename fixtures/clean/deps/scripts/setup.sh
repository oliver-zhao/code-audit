#!/bin/sh
set -eu
pip install --require-hashes -r requirements.txt
npm ci
pip install git+https://github.com/example/pkg.git@0123456789abcdef0123456789abcdef01234567#egg=pkg
