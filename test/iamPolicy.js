var checker = require("../index.js");
var assert = require("assert-plus");
var iamPolicy = require("../check/iamPolicy.js");

function test(template, options, expectedFindings, done) {
  checker.checkTemplate(template, options, function(err, findings) {
    if (err) {
      throw err;
    } else {
      if (findings.length !== expectedFindings) {
        console.log("findings", findings);
      }
      assert.equal(findings.length, expectedFindings, "findings");
      done();
    }
  });
}

function suite(templateJSON, done) {
  function wrap(policyDocument) {
    return JSON.parse(templateJSON.replace("\"$PolicyDocument\"", JSON.stringify(policyDocument)));
  }
  describe("Resource", function() {
    it("NotResource is not allowed", function(done) {
      test(wrap({
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": [
            "s3:PutObject"
          ],
          "NotResource": "arn:aws:s3:::name-of-bucket"
        }]
      }), {"iamPolicy": {"allow": [{"action": "*", "resource": "arn:aws:s3:::*"}]}}, 1, done);
    });
    it("string", function(done) {
      test(wrap({
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": [
            "s3:PutObject"
          ],
          "Resource": "arn:aws:s3:::name-of-bucket"
        }]
      }), {"iamPolicy": {"allow": [{"action": "*", "resource": "arn:aws:s3:::*"}]}}, 0, done);
    });
    it("array", function(done) {
      test(wrap({
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": [
            "s3:PutObject"
          ],
          "Resource": [
            "arn:aws:s3:::name-of-bucket"
          ]
        }]
      }), {"iamPolicy": {"allow": [{"action": "*", "resource": "arn:aws:s3:::*"}]}}, 0, done);
    });
    describe("allow", function() {
      it("allow specific s3 bucket", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::name-of-bucket"
          }]
        }), {"iamPolicy": {"allow": [{"action": "s3:*", "resource": "arn:aws:s3:::*"}]}}, 0, done);
      });
    });
    describe("deny", function() {
      it("deny all s3 buckets", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::name-of-bucket"
          }]
        }), {"iamPolicy": {"deny": [{"action": "s3:*", "resource": "arn:aws:s3:::*"}]}}, 1, done);
      });
    });
  });
  describe("Action", function() {
    it("NotAction is not allowed", function(done) {
      test(wrap({
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "NotAction": [
            "s3:PutObject"
          ],
          "Resource": "*"
        }]
      }), {"iamPolicy": {"allow": [{"action": "s3:PutObject", "resource": "*"}]}}, 1, done);
    });
    it("string", function(done) {
      test(wrap({
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": "s3:PutObject",
          "Resource": "*"
        }]
      }), {"iamPolicy": {"allow": [{"action": "s3:PutObject", "resource": "*"}]}}, 0, done);
    });
    it("array", function(done) {
      test(wrap({
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": [
            "s3:PutObject"
          ],
          "Resource": "*"
        }]
      }), {"iamPolicy": {"allow": [{"action": "s3:PutObject", "resource": "*"}]}}, 0, done);
    });
    describe("allow", function() {
      it("wildcard", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:PutObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"allow": [{"action": "s3:*", "resource": "*"}]}}, 0, done);
      });
      it("not allowed action in one statement with one action", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:PutObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"allow": [{"action": "s3:GetObject", "resource": "*"}]}}, 1, done);
      });
      it("allowed action in one statement with one action", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:GetObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"allow": [{"action": "s3:GetObject", "resource": "*"}]}}, 0, done);
      });
      it("allowed - but not used - action in one statement with one action", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:GetObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"allow": [
          {"action": "s3:GetObject", "resource": "*"},
          {"action": "s3:PutObject", "resource": "*"}
        ]}}, 0, done);
      });
      it("allowed actions in one statement with multiple actions", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:GetObject",
              "s3:PutObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"allow": [
          {"action": "s3:GetObject", "resource": "*"},
          {"action": "s3:PutObject", "resource": "*"}
        ]}}, 0, done);
      });
      it("allowed actions in multiple statements with one action", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:GetObject"
            ],
            "Resource": "*"
          }, {
            "Effect": "Allow",
            "Action": [
              "s3:PutObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"allow": [
          {"action": "s3:GetObject", "resource": "*"},
          {"action": "s3:PutObject", "resource": "*"}
        ]}}, 0, done);
      });
      it("ignore Effect = Deny", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Deny",
            "Action": [
              "s3:GetObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"allow": []}}, 0, done);
      });
    });
    describe("deny", function() {
      it("wildcard", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:PutObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"deny": [{"action": "s3:*", "resource": "*"}]}}, 1, done);
      });
      it("denied action in one statement with one action", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:GetObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"deny": [{"action": "s3:GetObject", "resource": "*"}]}}, 1, done);
      });
      it("not denied action in one statement with one action", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Allow",
            "Action": [
              "s3:PutObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"deny": [{"action": "s3:GetObject", "resource": "*"}]}}, 0, done);
      });
      it("ignore Effect := Deny", function(done) {
        test(wrap({
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Deny",
            "Action": [
              "s3:GetObject"
            ],
            "Resource": "*"
          }]
        }), {"iamPolicy": {"deny": []}}, 0, done);
      });
    });
  });
}

describe("iamPolicy", function() {
  it("empty", function(done) {
    test({}, {"iamPolicy": true}, 0, done);
  });
  describe("cross", function() {
    it("undefined with undefined", function() {
      var pairs = iamPolicy.cross(undefined, undefined);
      assert.deepEqual(pairs, [{"action": "*", "resource": "*"}]);
    });
    it("undefined with string", function() {
      var pairs = iamPolicy.cross(undefined, "r1");
      assert.deepEqual(pairs, [{"action": "*", "resource": "r1"}]);
    });
    it("string with undefined", function() {
      var pairs = iamPolicy.cross("a1", undefined);
      assert.deepEqual(pairs, [{"action": "a1", "resource": "*"}]);
    });
    it("string with string", function() {
      var pairs = iamPolicy.cross("a1", "r1");
      assert.deepEqual(pairs, [{"action": "a1", "resource": "r1"}]);
    });
    it("string with strings", function() {
      var pairs = iamPolicy.cross("a1", ["r1", "r2"]);
      assert.deepEqual(pairs, [{"action": "a1", "resource": "r1"}, {"action": "a1", "resource": "r2"}]);
    });
    it("strings with string", function() {
      var pairs = iamPolicy.cross(["a1", "a2"], "r1");
      assert.deepEqual(pairs, [{"action": "a1", "resource": "r1"}, {"action": "a2", "resource": "r1"}]);
    });
    it("strings with strings", function() {
      var pairs = iamPolicy.cross(["a1", "a2"], ["r1", "r2"]);
      assert.deepEqual(pairs, [{"action": "a1", "resource": "r1"}, {"action": "a1", "resource": "r2"}, {"action": "a2", "resource": "r1"}, {"action": "a2", "resource": "r2"}]);
    });
  });
  describe("ManagedPolicy", function(done) {
    suite(JSON.stringify({
      "Resources": {
        "ManagedPolicy": {
          "Type": "AWS::IAM::ManagedPolicy",
          "Properties": {
            "PolicyDocument": "$PolicyDocument"
          }
        }
      }
    }), done);
  });
  describe("Policy", function(done) {
    suite(JSON.stringify({
      "Resources": {
        "ManagedPolicy": {
          "Type": "AWS::IAM::Policy",
          "Properties": {
            "PolicyDocument": "$PolicyDocument"
          }
        }
      }
    }), done);
  });
  describe("User", function(done) {
    suite(JSON.stringify({
      "Resources": {
        "User": {
          "Type": "AWS::IAM::User",
          "Properties": {
            "Policies": [{
              "PolicyName": "test",
              "PolicyDocument": "$PolicyDocument"
            }]
          }
        }
      }
    }), done);
  });
  describe("Group", function(done) {
    suite(JSON.stringify({
      "Resources": {
        "Group": {
          "Type": "AWS::IAM::Group",
          "Properties": {
            "Policies": [{
              "PolicyName": "test",
              "PolicyDocument": "$PolicyDocument"
            }]
          }
        }
      }
    }), done);
  });
  describe("Role", function(done) {
    suite(JSON.stringify({
      "Resources": {
        "Role": {
          "Type": "AWS::IAM::Role",
          "Properties": {
            "Policies": [{
              "PolicyName": "s3",
              "PolicyDocument": "$PolicyDocument"
            }]
          }
        }
      }
    }), done);
  });
});
