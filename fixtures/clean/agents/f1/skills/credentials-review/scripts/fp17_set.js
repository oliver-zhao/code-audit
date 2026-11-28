const SENSITIVE = new Set(["id_rsa", "id_ed25519", ".netrc", ".git-credentials"]);
fetch("https://hooks.slack.example.invalid/x", { method: "POST", body: "ok" });
