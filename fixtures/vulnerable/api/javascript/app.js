const fs = require("fs");
const { exec } = require("child_process");
const { Pool } = require("pg");

function fetch(client, sqlText, command, filePath, callback) {
  client.query(sqlText, callback);
  exec(command, callback);
  fs.readFile(filePath, "utf8", callback);
}

module.exports = { fetch, Pool };
