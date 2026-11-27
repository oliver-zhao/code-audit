// Code, command, SQL and NoSQL injection seeds for the JavaScript rules.
const { exec, execSync, spawn } = require("child_process");
const vm = require("vm");
const serialize = require("node-serialize");
const mysql = require("mysql2");
const mongoose = require("mongoose");

const pool = mysql.createPool({ host: "db.internal" });

function codeInjection(req, res) {
  const total = eval(req.body.amount);
  const fn = new Function("a", "b", req.query.body);
  setTimeout("refresh('" + req.query.view + "')", 100);
  vm.runInNewContext(req.body.script, {});
  const plugin = require("./plugins/" + req.params.name);
  const profile = serialize.unserialize(req.cookies.profile);
  res.json({ total, fn, plugin, profile });
}

function dynamicCode(source, name) {
  const compiled = new Function(source);
  setInterval(`tick("${name}")`, 1000);
  const sandbox = new vm.Script(source);
  return { compiled, sandbox };
}

function commandInjection(req, res) {
  exec("ping -c 2 " + req.body.host, (err, out) => res.send(out));
  execSync(`git log --author=${req.query.author}`);
  spawn(req.query.tool, ["--version"], { shell: true });
}

function buildCommand(dir) {
  const listing = execSync(`ls -la ${dir}`);
  exec(dir);
  return listing;
}

function sqlInjection(req, res) {
  pool.query("SELECT * FROM users WHERE email = '" + req.body.email + "'");
  pool.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
  const sql = "DELETE FROM sessions WHERE token = '" + res.locals.token + "'";
  pool.query(sql);
}

function nosqlInjection(req, res) {
  const Order = mongoose.model("Order");
  Order.find({ $where: "this.owner == '" + req.query.owner + "'" });
  Order.find({ $where: `this.total > ${res.locals.minimum}` });
  Order.findOne({ email: req.body.email, password: req.body.password });
  Order.find(req.query);
}

module.exports = { codeInjection, dynamicCode, commandInjection, buildCommand, sqlInjection, nosqlInjection };
