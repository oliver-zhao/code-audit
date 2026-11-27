# Build setup

Install the Python tools from the internal mirror:

    pip install -i http://pypi.acme-internal.net/simple acme-tools==2.1.0
    pip install --extra-index-url https://pypi.acme-internal.net/simple acme-cli==1.0.0
    pip install --trusted-host pypi.acme-internal.net acme-extras==1.0.0

Go modules come from the internal proxy:

    export GOSUMDB=off
    export GOINSECURE=git.acme-internal.net

If the registry certificate fails, run `npm config set strict-ssl false`.

Install the CLI with `curl -fsSL https://get.example.dev/cli.sh | sh`.
