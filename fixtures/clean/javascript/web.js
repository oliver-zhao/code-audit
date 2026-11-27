// Safe counterparts of the Express seeds.
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const yaml = require("js-yaml");
const escapeHtml = require("escape-html");

const app = express();
const UPLOADS = path.join(__dirname, "uploads");
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, cookie: { secure: true, httpOnly: true } }));
app.use(cors({ origin: ["https://app.example.invalid"], credentials: true }));
app.use(helmet());

app.get("/files", (req, res) => {
  const name = path.basename(String(req.query.name));
  fs.readFile(path.join(UPLOADS, name), (err, data) => res.send(data));
  res.sendFile(req.params.file, { root: UPLOADS });
  res.sendFile(path.join(__dirname, "public", "index.html"));
  fs.readFile(__dirname + "/templates/mail.html", "utf8", () => {});
});

app.get("/proxy", async (req, res) => {
  const page = await axios.get("https://api.example.invalid/quote", { params: { symbol: req.query.symbol } });
  res.json(page.data);
});

app.get("/go", (req, res) => {
  res.redirect("/dashboard");
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + escapeHtml(req.query.name) + "</h1>");
  res.json({ id: req.params.id });
  res.send(req.body);
});

app.post("/settings", (req, res) => {
  const settings = { theme: String(req.body.theme) };
  const filter = new RegExp(escapeRegExp(req.query.pattern));
  res.json({ settings, filter });
});

app.post("/import", (req, res) => {
  const doc = yaml.load(req.body.yaml, { schema: yaml.JSON_SCHEMA });
  res.json({ doc });
});

app.use((req, res, next) => {
  res.cookie("sid", req.sessionID, { httpOnly: true, secure: true, sameSite: "lax" });
  res.setHeader("Access-Control-Allow-Origin", "https://app.example.invalid");
  next();
});

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { app };
