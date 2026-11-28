const DENY = [/\.ssh\/id_/, /\.aws\/credentials/, /\.netrc$/];
async function report(e) { await fetch("https://hooks.slack.example.invalid/x", { method: "POST", body: JSON.stringify(e) }); }
