/*
Checks allowed actions and resources of IAM policies. Wildcard * are supported.

A statement with NotAction is a finding. A statement with Effect != Allow is skipped.

Options: (Object)

* `action`: (Object)
 * `allow`: Array[String] List of allowed actions (wildcard * can be used) (whitelist)
 * `deny`: Array[String] List of denied actions (wildcard * can be used) (blacklist)
* `resource`: (Object)
 * `allow`: Array[String] List of allowed resources (wildcard * can be used) (whitelist)
 * `deny`: Array[String] List of denied resources (wildcard * can be used) (blacklist)
*/

var _ = require("lodash");
var wildstring = require("wildstring");

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

function extractAllowedResources(statements) {
  "use strict";
  return _.chain(statements)
    .filter(filterEffectAllow)
    .filter(function(statement) {
      return statement.Resource !== undefined;
    })
    .map("Resource")
    .flatten()
    .value();
}

function extractNotResources(statements) {
  "use strict";
  return _.chain(statements)
    .filter(function(statement) {
      return statement.NotResource !== undefined;
    })
    .map("NotResource")
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
  function actionChecker(object) {
    var statements = extractStatements(object);
    var allowedActions = extractAllowedActions(statements);
    var notActions = extractNotActions(statements);
    _.each(allowedActions, function(action) {
      if (options.action !== undefined && options.action.allow !== undefined && _.some(options.action.allow, function(allow) { return wildstring.match(allow, action); }) === false) {
        findings.push({
          logicalID: object.LogicalId,
          message: "Action " + action + " not allowed"
        });
      }
      if (options.action !== undefined && options.action.deny !== undefined && _.some(options.action.deny, function(deny) { return wildstring.match(deny, action); }) === true) {
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
  function resourceChecker(object) {
    var statements = extractStatements(object);
    var allowedResources = extractAllowedResources(statements);
    var notResources = extractNotResources(statements);
    _.each(allowedResources, function(resource) {
      if (options.resource !== undefined && options.resource.allow !== undefined && _.some(options.resource.allow, function(allow) { return wildstring.match(allow, resource); }) === false) {
        findings.push({
          logicalID: object.LogicalId,
          message: "Resource " + resource + " not allowed"
        });
      }
      if (options.resource !== undefined && options.resource.deny !== undefined && _.some(options.resource.deny, function(deny) { return wildstring.match(deny, resource); }) === true) {
        findings.push({
          logicalID: object.LogicalId,
          message: "Resource " + resource + " denied"
        });
      }
    });
    _.each(notResources, function(resource) {
      findings.push({
        logicalID: object.LogicalId,
        message: "NotResource " + resource + " is not allowed"
      });
    });
  }
  _.chain(objects)
    .filter(filterPartResource)
    .filter(filterTypeIamEntity)
    .each(actionChecker)
    .each(resourceChecker)
    .value();
  cb(null, findings);
};
