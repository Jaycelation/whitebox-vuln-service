const { execSync } = require("child_process");

function runCommand(command) {
  return execSync("sh -c " + command);
}

function runCount(limit) {
  return execSync("ls | head -n " + parseInt(limit, 10));
}

module.exports = { runCommand, runCount };
