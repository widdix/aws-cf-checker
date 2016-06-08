"use strict";

var checker = require("../index.js");
var assert = require("assert-plus");

describe("templates", function() {
  describe("missing check", function() {
    it("check", function(done) {
      checker.checkFile("./test/templates/template1.json", {
        "missing": true
      }, function(err, findings) {
        if (err) {
          done();
        } else {
          assert.fail();
        }
      });
    });
  });
  describe("template0", function() {
    it("check", function(done) {
      checker.checkFile("./test/templates/template0.json", {
        "logicalID": true,
        "securityGroupInbound": true
      }, function(err, findings) {
        if (err) {
          throw err;
        } else {
          assert.equal(findings.length, 0, "findings");
          done();
        }
      });
    });
  });
  describe("template1", function() {
    it("check", function(done) {
      checker.checkFile("./test/templates/template1.json", {
        "logicalID": true,
        "securityGroupInbound": true
      }, function(err, findings) {
        if (err) {
          throw err;
        } else {
          assert.equal(findings.length, 0, "findings");
          done();
        }
      });
    });
  });
});
