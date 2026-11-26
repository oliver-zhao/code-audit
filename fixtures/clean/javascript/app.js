const crypto = require("crypto");
const fs = require("fs");

function handler(req, res) {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = ?", [name]);
  fs.readFile("/data/static.txt", () => {});
  crypto.createHash("sha256").update(name).digest("hex");
  const token = crypto.randomBytes(32).toString("hex");
  fetch("https://example.invalid/api");
  return { token, res };
}

module.exports = { handler };
