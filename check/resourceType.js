/*
Checks if the resource types are allowed in the template. Wildcard * is supported.

If you `deny` something, everything that is not denied is allowed.
If you `allow` something, everything that is not allowed is denied.

Options: (Object)

* `deny`: (Array[String]) (whitelist, wildcard * can be used)
* `allow`: (Array[String]) (blacklist, wildcard * can be used)
*/

var _ = require("lodash");
var wildstring = require("wildstring");

function filterPartResource(object) {
  "use strict";
  return object.Part === "Resource";
}

exports.check = function(objects, options, cb) {
  "use strict";
  var findings = [];
  function checker(object) {
    if (options.allow !== undefined && _.some(options.allow, function(allow) {
      return wildstring.match(allow, object.Type);
    }) === false) {
      findings.push({
        logicalID: object.LogicalId,
        message: "Resource Type " + object.Type + " not allowed"
      });
    }
    if (options.deny !== undefined && _.some(options.deny, function(deny) {
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
