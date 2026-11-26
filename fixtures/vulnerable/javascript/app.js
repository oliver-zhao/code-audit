const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const serialize = require("node-serialize");
const axios = require("axios");

function handler(req, res) {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
  exec("ls " + name);
  eval(name);
  serialize.unserialize(name);
  fs.readFile("/data/" + name, () => {});
  crypto.createHash("md5").update(name).digest("hex");
  const token = Math.random().toString(36);
  fetch(req.query.url);
  axios.get(name, { httpsAgent: { rejectUnauthorized: false } });
}

module.exports = { handler };
