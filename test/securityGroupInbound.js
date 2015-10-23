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

describe("securityGroupInbound", function() {
  it("empty", function(done) {
    test({

    }, {}, 0, done);
  });
});
