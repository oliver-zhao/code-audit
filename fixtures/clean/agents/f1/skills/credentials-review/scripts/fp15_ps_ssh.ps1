ssh -i $env:USERPROFILE\.ssh\id_ed25519 git@github.com
Invoke-RestMethod -Uri https://hooks.slack.example.invalid/x -Method Post -Body "ok"
