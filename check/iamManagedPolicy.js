/*
Checks IAM Users, Groups and Roles for managed policy attachments. Wildcard * is supported.

Options: (Object)

* `allow`: (Array[String]) List of allowed ARNs (whitelist, wildcard * can be used)
* `deny`: (Array[String]) List of denied ARNs (blacklist, wildcard * can be used)
*/

var _ = require("lodash");
var wildstring = require("wildstring");

function filterPartResource(object) {
  "use strict";
  return object.Part === "Resource";
}

function filterTypeIamEntity(object) {
  "use strict";
  return object.Type === "AWS::IAM::Group" || object.Type === "AWS::IAM::Role" || object.Type === "AWS::IAM::User";
}

function extractManagedPolicyARNs(object) {
  "use strict";
  return object.Properties.ManagedPolicyArns;
}

exports.check = function(objects, options, cb) {
  "use strict";
  var findings = [];
  function checker(object) {
    var managedPolicyARNs = extractManagedPolicyARNs(object);
    _.each(managedPolicyARNs, function(managedPolicyARN) {
      if (options.allow !== undefined && _.some(options.allow, function(allow) {
        return wildstring.match(allow, managedPolicyARN);
      }) === false) {
        findings.push({
          logicalID: object.LogicalId,
          message: "ManagedPolicyARN " + managedPolicyARN + " not allowed"
        });
      }
      if (options.deny !== undefined && _.some(options.deny, function(deny) {
        return wildstring.match(deny, managedPolicyARN);
      }) === true) {
        findings.push({
          logicalID: object.LogicalId,
          message: "ManagedPolicyARN " + managedPolicyARN + " denied"
        });
      }
    });
  }
  _.chain(objects)
    .filter(filterPartResource)
    .filter(filterTypeIamEntity)
    .each(checker)
    .value();
  cb(null, findings);
};
