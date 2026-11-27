// Express server seeds: files, SSRF, redirects, XSS, CORS, cookies, sessions.
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const _ = require("lodash");
const yaml = require("js-yaml");
const libxmljs = require("libxmljs");

const app = express();
app.use(cookieParser("keyboard-cat-cookie"));
app.use(cors({ origin: true, credentials: true }));
app.use(helmet({ contentSecurityPolicy: false }));

app.get("/files", (req, res) => {
  fs.readFile(path.join(__dirname, "uploads", req.query.name), (err, data) => res.send(data));
  res.sendFile(req.params.file);
  res.download("/srv/exports/" + req.query.report);
});

function readUpload(dir, name) {
  return fs.readFileSync(dir + "/" + name);
}

function serveAsset(res, asset) {
  res.sendFile(path.resolve("public/assets/", asset));
  res.sendFile(asset);
}

app.get("/proxy", async (req, res) => {
  const page = await axios.get(req.query.url);
  const target = req.body.callback;
  const answer = await fetch(target);
  res.send(page.data + answer.status);
});

app.get("/go", (req, res) => {
  if (req.query.next) return res.redirect(req.query.next);
  const back = req.get("referer");
  return res.redirect(back);
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
  res.send(`<p>${req.params.id}</p>`);
});

app.post("/settings", (req, res) => {
  const settings = _.merge({}, req.body);
  const prefs = Object.assign({}, JSON.parse(req.body.prefs));
  const filter = new RegExp(req.query.pattern);
  res.json({ settings, prefs, filter });
});

app.post("/import", (req, res) => {
  const doc = yaml.load(req.body.yaml, { schema: yaml.DEFAULT_FULL_SCHEMA });
  const config = yaml.load(req.body.config);
  const xml = libxmljs.parseXmlString(req.body.xml, { noent: true });
  res.json({ doc, config, xml: xml.toString() });
});

app.use((req, res, next) => {
  res.cookie("sid", req.sessionID, { httpOnly: false });
  res.cookie("pref", "1", { secure: false });
  res.cookie("embed", "1", { secure: true, sameSite: "none" });
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

module.exports = { app, readUpload, serveAsset };
