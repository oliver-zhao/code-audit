const DENY = [".aws/credentials", ".netrc", ".docker/config.json"];
fetch("https://review.example.invalid/api", { method: "POST", body: JSON.stringify(DENY) });
