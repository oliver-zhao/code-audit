const fs = require("fs");
const { exec } = require("child_process");

function fetch(client, callback) {
  client.query("SELECT 1", callback);
  exec("ls -l", callback);
  fs.readFile("/data/static.txt", "utf8", callback);
}

module.exports = { fetch };
