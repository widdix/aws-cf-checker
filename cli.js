#!/usr/bin/env node
"use strict";

var checker = require("./index.js");
var fs = require("fs");
var argv = require("minimist")(process.argv.slice(2));

function checkCallback(err, findings) {
  if (err) {
    console.error(err.message);
    process.exit(2);
  } else {
    if (findings.length > 0) {
      findings.forEach(console.dir);
      process.exit(1);
    } else {
      process.exit(0);
    }
  }
}

function checkFile(file, options) {
  checker.checkFile(file, options, checkCallback);
}

function checkJSON(json, options) {
  checker.checkTemplate(JSON.parse(json), options, checkCallback);
}

var checks = require("./checks.json");
if (argv.checksFile) {
  var json = fs.readFileSync(argv.checksFile, {"encoding": "utf8"});
  checks = JSON.parse(json);
}

if (argv.templateFile) {
  checkFile(argv.templateFile, checks);
} else {
  var data = "";
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", function(chunk) {
    data += chunk;
  });
  process.stdin.on("end", function() {
    checkJSON(data, checks);
  });
}
