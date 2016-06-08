"use strict";

var _ = require("lodash");
var Netmask = require("netmask").Netmask;

var PRIVATE_IP_RANGES = [
  new Netmask("10.0.0.0/8"),
  new Netmask("172.16.0.0/12"),
  new Netmask("192.168.0.0/16")
];

module.exports = function(rangeOrAddress) {
  var block;
  if (rangeOrAddress.indexOf("/") !== -1) {
    block = new Netmask(rangeOrAddress);
  } else {
    block = rangeOrAddress;
  }
  return _.find(PRIVATE_IP_RANGES, function(range) {
    return range.contains(block);
  }) !== undefined;
};
