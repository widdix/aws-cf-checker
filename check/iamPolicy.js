/*
Checks allowed actions of IAM policies.

A statement with NotAction is a finding. A statement with Effect != Allow is skipped.

Options: (Object)

* `allow`: Array[String] List of allowed actions (whitelist)
* `deny`: Array[String] List of denied actions (blacklist)
*/

var _ = require("lodash");

function filterPartResource(object) {
  "use strict";
  return object.Part === "Resource";
}

function filterTypeIamEntity(object) {
  "use strict";
  return object.Type === "AWS::IAM::Group" || object.Type === "AWS::IAM::Role" || object.Type === "AWS::IAM::User" || object.Type === "AWS::IAM::Policy" || "AWS::IAM::ManagedPolicy";
}

function filterEffectAllow(statement) {
  "use strict";
  return statement.Effect === "Allow";
}

function extractAllowedActions(statements) {
  "use strict";
  return _.chain(statements)
    .filter(filterEffectAllow)
    .filter(function(statement) {
      return statement.Action !== undefined;
    })
    .map("Action")
    .flatten()
    .value();
}

function extractNotActions(statements) {
  "use strict";
  return _.chain(statements)
    .filter(function(statement) {
      return statement.NotAction !== undefined;
    })
    .map("NotAction")
    .flatten()
    .value();
}

function extractStatements(object) {
  "use strict";
  if (object.Type === "AWS::IAM::Policy" || object.Type === "AWS::IAM::ManagedPolicy") {
    return object.Properties.PolicyDocument.Statement;
  } else {
    return _.chain(object.Properties.Policies)
      .map(function(policy) {
        return policy.PolicyDocument.Statement;
      })
      .flatten()
      .value();
  }
}

exports.check = function(objects, options, cb) {
  "use strict";
  var findings = [];
  function checker(object) {
    var statements = extractStatements(object);
    var allowedActions = extractAllowedActions(statements);
    var notActions = extractNotActions(statements);
    _.each(allowedActions, function(action) {
      if (options.allow !== undefined && options.allow.indexOf(action) === -1) {
        findings.push({
          logicalID: object.LogicalId,
          message: "Action " + action + " not allowed"
        });
      }
      if (options.deny !== undefined && options.deny.indexOf(action) !== -1) {
        findings.push({
          logicalID: object.LogicalId,
          message: "Action " + action + " denied"
        });
      }
    });
    _.each(notActions, function(action) {
      findings.push({
        logicalID: object.LogicalId,
        message: "NotAction " + action + " is not allowed"
      });
    });
  }
  _.chain(objects)
    .filter(filterPartResource)
    .filter(filterTypeIamEntity)
    .each(checker)
    .value();
  cb(null, findings);
};
