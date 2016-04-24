/*
Checks if the resource types are allowed in the template.

If you `deny` something, everything that is not denied is allowed.
If you `allow` something, everything that is not allowed is denied.

Options: (Object)

* `deny`: Array[String]
* `allow`: Array[String]
*/

var _ = require("lodash");

function filterPartResource(object) {
  "use strict";
  return object.Part === "Resource";
}

exports.check = function(objects, options, cb) {
  "use strict";
  var findings = [];
  function checker(object) {
    if (options.allow !== undefined && options.allow.indexOf(object.Type) === -1) {
      findings.push({
        logicalID: object.LogicalId,
        message: "Resource Type " + object.Type + " not allowed"
      });
    }
    if (options.deny !== undefined && options.deny.indexOf(object.Type) !== -1) {
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
