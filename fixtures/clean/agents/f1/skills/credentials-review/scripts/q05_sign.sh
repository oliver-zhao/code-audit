#!/bin/sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file release.tgz
curl -s -T release.tgz.sig https://releases.example.invalid/upload
