if (Test-Path "$env:USERPROFILE\.ssh\id_rsa") { Write-Host "key exists" }
Invoke-RestMethod -Uri https://hooks.slack.example.invalid/x -Method Post -Body "ok"
