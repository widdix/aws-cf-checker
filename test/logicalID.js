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

function testDefault(template, expectedFindings, done) {
  test(template, {"logicalID": true}, expectedFindings, done);
}

function testPascal(template, expectedFindings, done) {
  test(template, {"logicalID": {"case": "pascal"}}, expectedFindings, done);
}

function testCamel(template, expectedFindings, done) {
  test(template, {"logicalID": {"case": "camel"}}, expectedFindings, done);
}

describe("logicalID", function() {
  describe("default case", function() {
    var testMethod = testDefault;
    it("empty", function(done) {
      testMethod({
      }, 0, done);
    });
    it("parts", function(done) {
      testMethod({
        "Parameters": {
          "res1": {}
        },
        "Mappings": {
          "res2": {}
        },
        "Conditions": {
          "res3": {}
        },
        "Resources": {
          "res4": {}
        },
        "Outputs": {
          "res5": {}
        }
      }, 5, done);
    });
    it("empty string", function(done) {
      testMethod({
        "Resources": {
          "": {
          }
        }
      }, 1, done);
    });
    it("lower case", function(done) {
      testMethod({
        "Resources": {
          "res": {
          }
        }
      }, 1, done);
    });
    it("one char", function(done) {
      testMethod({
        "Resources": {
          "R": {
          }
        }
      }, 0, done);
    });
    it("only upper case", function(done) {
      testMethod({
        "Resources": {
          "ABC": {
          }
        }
      }, 0, done);
    });
    it("valid1", function(done) {
      testMethod({
        "Resources": {
          "ValidPascal1Case": {
          }
        }
      }, 0, done);
    });
    it("valid2", function(done) {
      testMethod({
        "Resources": {
          "Valid": {
          }
        }
      }, 0, done);
    });
    it("valid3", function(done) {
      testMethod({
        "Resources": {
          "Valid1": {
          }
        }
      }, 0, done);
    });
  });
  describe("pascal case", function() {
    var testMethod = testPascal;
    it("empty", function(done) {
      testMethod({
      }, 0, done);
    });
    it("parts", function(done) {
      testMethod({
        "Parameters": {
          "res1": {}
        },
        "Mappings": {
          "res2": {}
        },
        "Conditions": {
          "res3": {}
        },
        "Resources": {
          "res4": {}
        },
        "Outputs": {
          "res5": {}
        }
      }, 5, done);
    });
    it("empty string", function(done) {
      testMethod({
        "Resources": {
          "": {
          }
        }
      }, 1, done);
    });
    it("lower case", function(done) {
      testMethod({
        "Resources": {
          "res": {
          }
        }
      }, 1, done);
    });
    it("one char", function(done) {
      testMethod({
        "Resources": {
          "R": {
          }
        }
      }, 0, done);
    });
    it("only upper case", function(done) {
      testMethod({
        "Resources": {
          "ABC": {
          }
        }
      }, 0, done);
    });
    it("valid1", function(done) {
      testMethod({
        "Resources": {
          "ValidPascal1Case": {
          }
        }
      }, 0, done);
    });
    it("valid2", function(done) {
      testMethod({
        "Resources": {
          "Valid": {
          }
        }
      }, 0, done);
    });
    it("valid3", function(done) {
      testMethod({
        "Resources": {
          "Valid1": {
          }
        }
      }, 0, done);
    });
  });
  describe("camel case", function() {
    var testMethod = testCamel;
    it("empty", function(done) {
      testMethod({
      }, 0, done);
    });
    it("parts", function(done) {
      testMethod({
        "Parameters": {
          "Res1": {}
        },
        "Mappings": {
          "Res2": {}
        },
        "Conditions": {
          "Res3": {}
        },
        "Resources": {
          "Res4": {}
        },
        "Outputs": {
          "Res5": {}
        }
      }, 5, done);
    });
    it("empty string", function(done) {
      testMethod({
        "Resources": {
          "": {
          }
        }
      }, 1, done);
    });
    it("upper case", function(done) {
      testMethod({
        "Resources": {
          "Res": {
          }
        }
      }, 1, done);
    });
    it("one char", function(done) {
      testMethod({
        "Resources": {
          "r": {
          }
        }
      }, 0, done);
    });
    it("only upper case", function(done) {
      testMethod({
        "Resources": {
          "ABC": {
          }
        }
      }, 1, done);
    });
    it("valid1", function(done) {
      testMethod({
        "Resources": {
          "validCamel1Case": {
          }
        }
      }, 0, done);
    });
    it("valid2", function(done) {
      testMethod({
        "Resources": {
          "valid": {
          }
        }
      }, 0, done);
    });
    it("valid3", function(done) {
      testMethod({
        "Resources": {
          "valid1": {
          }
        }
      }, 0, done);
    });
  });
});
