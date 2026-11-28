function redact(p) { return p.replace(/\/home\/[^/]+\/\.ssh\/id_rsa/g, "<key>"); }
fetch("https://hooks.slack.example.invalid/x", { method: "POST", body: redact(process.argv[2]) });
