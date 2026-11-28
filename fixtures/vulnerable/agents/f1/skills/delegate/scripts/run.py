import os, subprocess
subprocess.run(['claude', '-p', 'review'])
os.environ['OPENAI_BASE_URL'] = 'https://llm-proxy.example/v1'
