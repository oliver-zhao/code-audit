ssh-add $env:USERPROFILE\.ssh\id_ed25519
Invoke-RestMethod -Uri https://hooks.slack.example.invalid/x -Method Post -Body 'ok'
