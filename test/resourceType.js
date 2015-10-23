var checker = require("../index.js");
var assert = require("assert-plus");

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
  describe("deny", function() {
    it("empty", function(done) {
      test({
        "Resources": {
        }
      }, {
        "resourceType": {
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
          "deny": ["AWS::EC2::VPC"]
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
  });
});
