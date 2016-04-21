/*
Checks logical ids of your template.

Options: (Object)

* `case`: Enum["pascal", "camel"] (default: "pascal")
*/

var _ = require("lodash");

var CASES = {
  "camel": /^([a-z0-9]+)([A-Z][a-z0-9]+)*/,
  "pascal": /^([A-Z][a-z0-9]*)+/
};

exports.check = function(objects, options, cb) {
  "use strict";
  var findings = [];
  var c = options["case"] || "pascal";
  var regex = CASES[c];
  function checker(object) {
    if (regex.test(object.LogicalId) === false) {
      findings.push({
        logicalID: object.LogicalId,
        message: "Logical ID does not match " + c + "case"
      });
    }
  }
  _.each(objects, checker);
  cb(null, findings);
};
