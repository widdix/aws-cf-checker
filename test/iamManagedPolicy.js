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

describe("iamManagedPolicy", function() {
  it("empty", function(done) {
    test({

    }, {"iamManagedPolicy": {}}, 0, done);
  });
  describe("Role", function() {
    describe("allow", function() {
      it("nothing attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("empty attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": []
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("one policy attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("one policy attached, allow []", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: []}}, 1, done);
      });
      it("two policies attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("two policies attached, allow only one by ARN", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/AdministratorAccess"]}}, 1, done);
      });
      it("two policies attached, allow only one by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 1, done);
      });
      it("two ReadOnly policies attached, allow both by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AmazonGlacierReadOnlyAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 0, done);
      });
    });
    describe("deny", function() {
      it("nothing attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 0, done);
      });
      it("empty attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": []
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 0, done);
      });
      it("one policy attached, deny []", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: []}}, 0, done);
      });
      it("one policy attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 1, done);
      });
      it("two policies attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 2, done);
      });
      it("two policies attached, deny only one by ARN", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/AdministratorAccess"]}}, 1, done);
      });
      it("two policies attached, deny only one by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 1, done);
      });
      it("two ReadOnly policies attached, deny both by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AmazonGlacierReadOnlyAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 2, done);
      });
    });
  });
  describe("User", function() {
    describe("allow", function() {
      it("nothing attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("empty attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": []
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("one policy attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("two policies attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("two policies attached, allow only one by ARN", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/AdministratorAccess"]}}, 1, done);
      });
      it("two policies attached, allow only one by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 1, done);
      });
      it("two ReadOnly policies attached, allow both by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AmazonGlacierReadOnlyAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 0, done);
      });
    });
    describe("deny", function() {
      it("nothing attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 0, done);
      });
      it("empty attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": []
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 0, done);
      });
      it("one policy attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 1, done);
      });
      it("two policies attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 2, done);
      });
      it("two policies attached, deny only one by ARN", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/AdministratorAccess"]}}, 1, done);
      });
      it("two policies attached, deny only one by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 1, done);
      });
      it("two ReadOnly policies attached, deny both by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::User",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AmazonGlacierReadOnlyAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 2, done);
      });
    });
  });
  describe("Group", function() {
    describe("allow", function() {
      it("nothing attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("empty attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": []
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("one policy attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("two policies attached, allow [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["*"]}}, 0, done);
      });
      it("two policies attached, allow only one by ARN", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/AdministratorAccess"]}}, 1, done);
      });
      it("two policies attached, allow only one by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 1, done);
      });
      it("two ReadOnly policies attached, allow both by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AmazonGlacierReadOnlyAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {allow: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 0, done);
      });
    });
    describe("deny", function() {
      it("nothing attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 0, done);
      });
      it("empty attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": []
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 0, done);
      });
      it("one policy attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 1, done);
      });
      it("two policies attached, deny [*]", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["*"]}}, 2, done);
      });
      it("two policies attached, deny only one by ARN", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/AdministratorAccess"]}}, 1, done);
      });
      it("two policies attached, deny only one by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AdministratorAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 1, done);
      });
      it("two ReadOnly policies attached, deny both by wildcard", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Group",
              "Properties": {
                "ManagedPolicyArns": [
                  "arn:aws:iam::aws:policy/AmazonGlacierReadOnlyAccess",
                  "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
                ]
              }
            }
          }
        }, {"iamManagedPolicy": {deny: ["arn:aws:iam::aws:policy/*ReadOnlyAccess"]}}, 2, done);
      });
    });
  });
});
