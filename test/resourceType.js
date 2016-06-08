"use strict";

var checker = require("../index.js");
var assert = require("assert-plus");
// TODO test wildcard
function test(template, options, expectedFindings, done) {
  checker.checkTemplate(template, options, function(err, findings) {
    if (err) {
      throw err;
    } else {
      assert.equal(findings.length, expectedFindings, "findings");
      done();
    }
  });
}

describe("resourceType", function() {
  describe("implicit deny", function() {
    it("empty", function(done) {
      test({
        "Resources": {
        }
      }, {
        "resourceType": {
        }
      }, 0, done);
    });
    it("nothing allowed", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
        }
      }, 1, done);
    });
    it("allow wildcard does not match", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["AWS::IAM::*"]
        }
      }, 1, done);
    });
    it("allow wildcard does match", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["AWS::EC2::*"]
        }
      }, 0, done);
    });
  });
  describe("explicit deny", function() {
    it("empty", function(done) {
      test({
        "Resources": {
        }
      }, {
        "resourceType": {
          "allow": ["*"],
          "deny": ["AWS::EC2::VPC"]
        }
      }, 0, done);
    });
    it("no hit", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["*"],
          "deny": ["AWS::EC2::VPC"]
        }
      }, 0, done);
    });
    it("hit", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["*"],
          "deny": ["AWS::EC2::VPC"]
        }
      }, 1, done);
    });
    it("no hit by wildcard", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["*"],
          "deny": ["AWS::IAM::*"]
        }
      }, 0, done);
    });
    it("hit by wildcard", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["*"],
          "deny": ["*"]
        }
      }, 1, done);
    });
  });
  describe("allow", function() {
    it("empty", function(done) {
      test({
        "Resources": {
        }
      }, {
        "resourceType": {
          "allow": ["AWS::EC2::VPC"]
        }
      }, 0, done);
    });
    it("hit", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["AWS::EC2::VPC"]
        }
      }, 1, done);
    });
    it("no hit", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["AWS::EC2::VPC"]
        }
      }, 0, done);
    });
    it("hit by wildcard", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["AWS::IAM::*"]
        }
      }, 1, done);
    });
    it("no hit by wildcard", function(done) {
      test({
        "Resources": {
          "VPC": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
            }
          }
        }
      }, {
        "resourceType": {
          "allow": ["*"]
        }
      }, 0, done);
    });
  });
});
