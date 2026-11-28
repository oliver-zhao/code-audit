#!/bin/sh
KCFG=${KUBECONFIG:-~/.kube/config}
curl -s -X POST -d "cluster ready" https://hooks.slack.example.invalid/x
