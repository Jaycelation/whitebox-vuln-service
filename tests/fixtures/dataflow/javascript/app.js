const express = require("express");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const { exec } = require("child_process");
const { runCommand, runCount } = require("./helpers");
const { findUser, userName, pool } = require("./db");
const { fetchRemote } = require("./remote");

const app = express();

app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, () => res.end());  // EXPECT command-injection direct
});

app.get("/run2", (req, res) => {
  res.json(runCommand(req.query.cmd));  // EXPECT command-injection cross-file
});

app.get("/count", (req, res) => {
  res.json(runCount(req.query.n));
});

app.get("/user", async (req, res) => {
  res.json(await findUser(req.body.name));  // EXPECT sql-injection cross-file
});

app.get("/user2", async (req, res) => {
  res.json(await pool.query("SELECT * FROM users WHERE id = " + parseInt(req.query.id, 10)));
});

app.get("/fetch", async (req, res) => {
  res.json(await axios.get(req.query.url));  // EXPECT ssrf direct
});

app.get("/fetch2", async (req, res) => {
  res.send(await fetchRemote(req.query.url));  // EXPECT ssrf cross-file typescript; EXPECT template-injection (remote response reflected)
});

app.get("/file", (req, res) => {
  fs.readFile(path.join(__dirname, req.params.file), (err, data) => res.end(data));  // EXPECT path-traversal direct
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + userName(req) + "</h1>");  // EXPECT template-injection source wrapper
});

app.get("/next", (req, res) => {
  res.redirect(req.query.next);  // EXPECT open-redirect direct
});

app.get("/static", (req, res) => {
  exec("uptime", () => res.end());
});
