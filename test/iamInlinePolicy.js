var checker = require("../index.js");
var assert = require("assert-plus");

function test(template, options, expectedFindings, done) {
  checker.checkTemplate(template, options, function(err, findings) {
    if (err) {
      throw err;
    } else {
      if (findings.length !== expectedFindings) {
        console.log(findings);
      }
      assert.equal(findings.length, expectedFindings, "findings");
      done();
    }
  });
}

describe("iamInlinePolicy", function() {
  it("empty", function(done) {
    test({

    }, {"iamInlinePolicy": true}, 0, done);
  });
  describe("Policy", function() {
    it("with not allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
              "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                  "Effect": "Allow",
                  "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                  ],
                  "Resource": "*"
                }]
              }
            }
          }
        }
      }, {"iamInlinePolicy": false}, 1, done);
    });
    it("with allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
              "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                  "Effect": "Allow",
                  "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                  ],
                  "Resource": "*"
                }]
              }
            }
          }
        }
      }, {"iamInlinePolicy": true}, 0, done);
    });
    it("with default", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Policy",
            "Properties": {
              "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                  "Effect": "Allow",
                  "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                  ],
                  "Resource": "*"
                }]
              }
            }
          }
        }
      }, {"iamInlinePolicy": true}, 0, done);
    });
  });
  describe("User", function() {
    it("with not allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::User",
            "Properties": {
              "Policies": [{
                "PolicyName": "s3",
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:GetObject",
                      "s3:ListBucket"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamInlinePolicy": false}, 1, done);
    });
    it("with allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::User",
            "Properties": {
              "Policies": [{
                "PolicyName": "s3",
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:GetObject",
                      "s3:ListBucket"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamInlinePolicy": true}, 0, done);
    });
  });
  describe("Group", function() {
    it("with not allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Group",
            "Properties": {
              "Policies": [{
                "PolicyName": "s3",
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:GetObject",
                      "s3:ListBucket"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamInlinePolicy": false}, 1, done);
    });
    it("with allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Group",
            "Properties": {
              "Policies": [{
                "PolicyName": "s3",
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:GetObject",
                      "s3:ListBucket"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamInlinePolicy": true}, 0, done);
    });
  });
  describe("Role", function() {
    it("with not allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Role",
            "Properties": {
              "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                  "Effect": "Allow",
                  "Principal": {
                    "Service": ["ec2.amazonaws.com"]
                  },
                  "Action": ["sts:AssumeRole"]
                }]
              },
              "Policies": [{
                "PolicyName": "s3",
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:GetObject",
                      "s3:ListBucket"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamInlinePolicy": false}, 1, done);
    });
    it("with allowed inline policy", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Role",
            "Properties": {
              "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                  "Effect": "Allow",
                  "Principal": {
                    "Service": ["ec2.amazonaws.com"]
                  },
                  "Action": ["sts:AssumeRole"]
                }]
              },
              "Policies": [{
                "PolicyName": "s3",
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:GetObject",
                      "s3:ListBucket"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamInlinePolicy": true}, 0, done);
    });
  });
});
