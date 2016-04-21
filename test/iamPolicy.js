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

describe("iamPolicy", function() {
  it("empty", function(done) {
    test({

    }, {"iamPolicy": true}, 0, done);
  });
  describe("ManagedPolicy", function() {
    describe("Resource", function() {
      it("NotResource is not allowed", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::ManagedPolicy",
              "Properties": {
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:PutObject"
                    ],
                    "NotResource": "arn:aws:s3:::name-of-bucket"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"resource": {"allow": ["arn:aws:s3:::*"]}}}, 1, done);
      });
      it("string", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::ManagedPolicy",
              "Properties": {
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:PutObject"
                    ],
                    "Resource": "arn:aws:s3:::name-of-bucket"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"resource": {"allow": ["arn:aws:s3:::*"]}}}, 0, done);
      });
      it("array", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::ManagedPolicy",
              "Properties": {
                "PolicyDocument": {
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
                }
              }
            }
          }
        }, {"iamPolicy": {"resource": {"allow": ["arn:aws:s3:::*"]}}}, 0, done);
      });
      describe("allow", function() {
        it("allow specific s3 bucket", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "arn:aws:s3:::name-of-bucket"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"resource": {"allow": ["arn:aws:s3:::*"]}}}, 0, done);
        });
      });
      describe("deny", function() {
        it("deny all s3 buckets", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "arn:aws:s3:::name-of-bucket"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"resource": {"deny": ["arn:aws:s3:::*"]}}}, 1, done);
        });
      });
    });
    describe("Action", function() {
      it("NotAction is not allowed", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::ManagedPolicy",
              "Properties": {
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "NotAction": [
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:PutObject"]}}}, 1, done);
      });
      it("string", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::ManagedPolicy",
              "Properties": {
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:PutObject"]}}}, 0, done);
      });
      it("array", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::ManagedPolicy",
              "Properties": {
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:PutObject"]}}}, 0, done);
      });
      describe("allow", function() {
        it("wildcard", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"allow": ["s3:*"]}}}, 0, done);
        });
        it("not allowed action in one statement with one action", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 1, done);
        });
        it("allowed action in one statement with one action", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 0, done);
        });
        it("allowed - but not used - action in one statement with one action", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
        });
        it("allowed actions in one statement with multiple actions", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
        });
        it("allowed actions in multiple statements with one action", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
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
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
        });
        it("ignore Effect = Deny", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"allow": []}}}, 0, done);
        });
      });
      describe("deny", function() {
        it("wildcard", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"deny": ["s3:*"]}}}, 1, done);
        });
        it("denied action in one statement with one action", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 1, done);
        });
        it("not denied action in one statement with one action", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 0, done);
        });
        it("ignore Effect := Deny", function(done) {
          test({
            "Resources": {
              "Test": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }
              }
            }
          }, {"iamPolicy": {"action": {"deny": []}}}, 0, done);
        });
      });
    });
  });
  describe("User", function() {
    it("NotAction is not allowed", function(done) {
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
                    "NotAction": [
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamPolicy": {"action": {"allow": []}}}, 1, done);
    });
    describe("allow", function() {
      it("not allowed action in one statement with one action", function(done) {
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
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 1, done);
      });
      it("allowed action in one statement with one action", function(done) {
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
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 0, done);
      });
      it("allowed - but not used - action in one statement with one action", function(done) {
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
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in one statement with multiple actions", function(done) {
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
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in multiple statements with one action", function(done) {
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
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("ignore Effect = Deny", function(done) {
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
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": []}}}, 0, done);
      });
    });
    describe("deny", function() {
      it("denied action in one statement with one action", function(done) {
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
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 1, done);
      });
      it("not denied action in one statement with one action", function(done) {
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
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 0, done);
      });
      it("ignore Effect := Deny", function(done) {
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
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": []}}}, 0, done);
      });
    });
  });
  describe("Group", function() {
    it("NotAction is not allowed", function(done) {
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
                    "NotAction": [
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamPolicy": {"action": {"allow": []}}}, 1, done);
    });
    describe("allow", function() {
      it("not allowed action in one statement with one action", function(done) {
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
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 1, done);
      });
      it("allowed action in one statement with one action", function(done) {
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
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 0, done);
      });
      it("allowed - but not used - action in one statement with one action", function(done) {
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
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in one statement with multiple actions", function(done) {
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
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in multiple statements with one action", function(done) {
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
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("ignore Effect = Deny", function(done) {
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
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": []}}}, 0, done);
      });
    });
    describe("deny", function() {
      it("denied action in one statement with one action", function(done) {
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
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 1, done);
      });
      it("not denied action in one statement with one action", function(done) {
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
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 0, done);
      });
      it("ignore Effect := Deny", function(done) {
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
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": []}}}, 0, done);
      });
    });
  });
  describe("Role", function() {
    it("NotAction is not allowed", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::Role",
            "Properties": {
              "Policies": [{
                "PolicyName": "s3",
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "NotAction": [
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }]
            }
          }
        }
      }, {"iamPolicy": {"action": {"allow": []}}}, 1, done);
    });
    describe("allow", function() {
      it("not allowed action in one statement with one action", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 1, done);
      });
      it("allowed action in one statement with one action", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 0, done);
      });
      it("allowed - but not used - action in one statement with one action", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in one statement with multiple actions", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in multiple statements with one action", function(done) {
        test({
          "Resources": {
            "Test": {
             "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
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
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("ignore Effect = Deny", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": []}}}, 0, done);
      });
    });
    describe("deny", function() {
      it("denied action in one statement with one action", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 1, done);
      });
      it("not denied action in one statement with one action", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Allow",
                      "Action": [
                        "s3:PutObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 0, done);
      });
      it("ignore Effect := Deny", function(done) {
        test({
          "Resources": {
            "Test": {
             "Type": "AWS::IAM::Role",
              "Properties": {
                "Policies": [{
                  "PolicyName": "s3",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                      "Effect": "Deny",
                      "Action": [
                        "s3:GetObject"
                      ],
                      "Resource": "*"
                    }]
                  }
                }]
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": []}}}, 0, done);
      });
    });
  });
  describe("Policy", function() {
    it("NotAction is not allowed", function(done) {
      test({
        "Resources": {
          "Test": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
              "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                  "Effect": "Allow",
                  "NotAction": [
                    "s3:PutObject"
                  ],
                  "Resource": "*"
                }]
              }
            }
          }
        }
      }, {"iamPolicy": {"action": {"allow": []}}}, 1, done);
    });
    describe("allow", function() {
      it("not allowed action in one statement with one action", function(done) {
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
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 1, done);
      });
      it("allowed action in one statement with one action", function(done) {
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
                      "s3:GetObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject"]}}}, 0, done);
      });
      it("allowed - but not used - action in one statement with one action", function(done) {
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
                      "s3:GetObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in one statement with multiple actions", function(done) {
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
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("allowed actions in multiple statements with one action", function(done) {
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
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": ["s3:GetObject", "s3:PutObject"]}}}, 0, done);
      });
      it("ignore Effect = Deny", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Policy",
              "Properties": {
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Deny",
                    "Action": [
                      "s3:GetObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"allow": []}}}, 0, done);
      });
    });
    describe("deny", function() {
      it("denied action in one statement with one action", function(done) {
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
                      "s3:GetObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 1, done);
      });
      it("not denied action in one statement with one action", function(done) {
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
                      "s3:PutObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": ["s3:GetObject"]}}}, 0, done);
      });
      it("ignore Effect := Deny", function(done) {
        test({
          "Resources": {
            "Test": {
              "Type": "AWS::IAM::Policy",
              "Properties": {
                "PolicyDocument": {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Deny",
                    "Action": [
                      "s3:GetObject"
                    ],
                    "Resource": "*"
                  }]
                }
              }
            }
          }
        }, {"iamPolicy": {"action": {"deny": []}}}, 0, done);
      });
    });
  });
});
