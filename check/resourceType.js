/*
Checks if the resource types are allowed in the template. Wildcard * is supported.

By default, nothing is allowed (implicit deny). If you deny something it overrides what you allowed (explicit deny).

Options: (Object)

* `deny`: (Array[String]) (whitelist, wildcard * can be used)
* `allow`: (Array[String]) (blacklist, wildcard * can be used)
*/
"use strict";

var _ = require("lodash");
var wildstring = require("wildstring");

function filterPartResource(object) {
  return object.Part === "Resource";
}

exports.check = function(objects, options, cb) {
  var findings = [];
  function checker(object) {
    if (_.some(options.allow, function(allow) {
      return wildstring.match(allow, object.Type);
    }) === false) {
      findings.push({
        logicalID: object.LogicalId,
        message: "Resource Type " + object.Type + " not allowed"
      });
    }
    if (_.some(options.deny, function(deny) {
      return wildstring.match(deny, object.Type);
    }) === true) {
      findings.push({
        logicalID: object.LogicalId,
        message: "Resource Type " + object.Type + " denied"
      });
    }
  }
  _.chain(objects)
    .filter(filterPartResource)
    .each(checker)
    .value();
  cb(null, findings);
};
