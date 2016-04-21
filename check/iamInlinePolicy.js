/*
Checks IAM Users, Groups and Roles for inline policies.

Options: (Boolean)

`true` := inline policies are allowed
`false` := inline policies are denied
*/

var _ = require("lodash");

function filterPartResource(object) {
  "use strict";
  return object.Part === "Resource";
}

function filterTypeIamEntity(object) {
  "use strict";
  return object.Type === "AWS::IAM::Group" || object.Type === "AWS::IAM::Role" || object.Type === "AWS::IAM::User" || object.Type === "AWS::IAM::Policy";
}

exports.check = function(objects, options, cb) {
  "use strict";
  var findings = [];
  function checker(object) {
    if (options === false) {
      if (object.Type === "AWS::IAM::Policy" || object.Properties.Policies !== undefined) {
        findings.push({
          logicalID: object.LogicalId,
          message: "Inline Policy not allowed"
        });
      }
    }
  }
  _.chain(objects)
    .filter(filterPartResource)
    .filter(filterTypeIamEntity)
    .each(checker)
    .value();
  cb(null, findings);
};
