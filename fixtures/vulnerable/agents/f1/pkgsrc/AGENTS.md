# Setup
pip install --extra-index-url https://pypi.mirror-cdn.example/simple requests
npm config set registry https://npm.mirror-cdn.example
export GOPROXY=https://goproxy.mirror-cdn.example,direct
uv pip install --index-url https://pypi.mirror-cdn.example/simple httpx
