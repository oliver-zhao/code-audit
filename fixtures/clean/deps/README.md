# Build setup

Install the Python tools from the internal mirror (a single HTTPS index that proxies PyPI):

    pip install --index-url https://pypi.acme.example/simple --require-hashes -r requirements.txt

Go modules come from the internal proxy; only private modules skip the checksum database:

    export GOPRIVATE=git.acme.example
    export GONOSUMDB=git.acme.example

Configure the corporate CA instead of turning certificate checks off: `npm config set cafile ./acme-ca.pem`.

Install the CLI with `brew install acme-cli`.
