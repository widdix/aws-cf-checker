var privateIpRange = require("../lib/privateIpRange.js");
var assert = require("assert-plus");

describe("privateIpRange", function() {
  describe("10.0.0.0/8", function() {
    it("full", function() {
      assert.equal(privateIpRange("10.0.0.0/8"), true);
    });
    it("range inside", function() {
      assert.equal(privateIpRange("10.0.0.0/16"), true);
    });
    it("ip inside", function() {
      assert.equal(privateIpRange("10.0.0.10"), true);
    });
  });
  describe("172.16.0.0/12", function() {
    it("full", function() {
      assert.equal(privateIpRange("172.16.0.0/12"), true);
    });
    it("range inside", function() {
      assert.equal(privateIpRange("172.16.0.0/24"), true);
    });
    it("ip inside", function() {
      assert.equal(privateIpRange("172.16.0.10"), true);
    });
  });
  describe("192.168.0.0/16", function() {
    it("full", function() {
      assert.equal(privateIpRange("192.168.0.0/16"), true);
    });
    it("range inside", function() {
      assert.equal(privateIpRange("192.168.0.0/24"), true);
    });
    it("ip inside", function() {
      assert.equal(privateIpRange("192.168.0.10"), true);
    });
  });
  describe("public", function() {
    it("range", function() {
      assert.equal(privateIpRange("52.95.60.0/24"), false);
    });
    it("ip outside", function() {
      assert.equal(privateIpRange("88.128.80.117"), false);
    });
  });
});
