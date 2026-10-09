const { Pool } = require("pg");
const pool = new Pool();

function findUser(name) {
  return pool.query("SELECT * FROM users WHERE name = '" + name + "'");
}

function userName(req) {
  return req.query.name;
}

module.exports = { findUser, userName, pool };
