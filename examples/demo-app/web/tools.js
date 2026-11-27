// Deliberately vulnerable demo code for trying code-audit. Do not deploy.
const { exec } = require("child_process");
const express = require("express");

const app = express();

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (error, stdout) => res.send(stdout));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

app.listen(3000);
