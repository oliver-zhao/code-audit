// Safe counterparts of the injection seeds.
const { execFile, spawn } = require("child_process");
const mysql = require("mysql2");
const mongoose = require("mongoose");

const pool = mysql.createPool({ host: "db.internal" });

function parseInput(req, res) {
  const total = Number(req.body.amount);
  const fn = new Function("a", "b", "return a + b");
  setTimeout(() => refresh(req.query.view), 100);
  const plugins = { csv: require("./plugins/csv") };
  const plugin = plugins[req.params.name];
  const profile = JSON.parse(req.cookies.profile);
  const sample = "eval(req.body.amount) is unsafe";
  res.json({ total, fn, plugin, profile, sample });
}

function runTools(req, res) {
  execFile("ping", ["-c", "2", req.body.host], (err, out) => res.send(out));
  spawn("git", ["log", "--author", req.query.author]);
  const pattern = /(\d+)/;
  const matches = pattern.exec(req.query.text);
  return matches;
}

function queries(req, res) {
  pool.query("SELECT * FROM users WHERE email = ?", [req.body.email]);
  pool.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
  const label = "Select an item from the list: " + req.query.item;
  const columns = ["id", "email"];
  pool.query("SELECT " + columns.join(", ") + " FROM users WHERE id = ?", [req.params.id]);
  res.json({ label });
}

function mongo(req, res) {
  const Order = mongoose.model("Order");
  Order.find({ owner: String(req.query.owner) });
  Order.find({ $where: "this.total > this.minimum" });
  Order.findOne({ email: String(req.body.email) });
  res.json({});
}

/**
 * Do not write exec("ls " + dir) or db.query("SELECT * FROM t WHERE a = '" + a + "'").
 */
function refresh(view) {
  return view;
}

module.exports = { parseInput, runTools, queries, mongo };
