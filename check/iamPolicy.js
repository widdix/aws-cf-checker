/*
Checks allowed actions and resources of IAM policy statements. Wildcard * is supported.

A statement with NotAction is a finding.
A statement with Effect != Allow is skipped.

By default, nothing is allowed (implicit deny). If you deny something it overrides what you allowed (explicit deny).

Options: (Object)

* `allow`: (Array[Object]) List of allowed actions & resources  (whitelist)
 * `action`: (String | Array[String]) IAM action (wildcard * can be used)
 * `resource`: (String | Array[String]) IAM resource (wildcard * can be used)
* `deny`: (Array[Object]) List of denied actions & resources (blacklist)
 * `action`: (String | Array[String]) IAM action (wildcard * can be used)
 * `resource`: (String | Array[String]) IAM resource (wildcard * can be used)
*/
"use strict";

var _ = require("lodash");
var wildstring = require("wildstring");

function filterPartResource(object) {
  return object.Part === "Resource";
}

function filterTypeIamEntity(object) {
  return object.Type === "AWS::IAM::Group" || object.Type === "AWS::IAM::Role" || object.Type === "AWS::IAM::User" || object.Type === "AWS::IAM::Policy" || "AWS::IAM::ManagedPolicy";
}

function filterEffectAllow(statement) {
  return statement.Effect === "Allow";
}

function extractNotActions(statements) {
  return _.chain(statements)
    .filter(function(statement) {
      return statement.NotAction !== undefined;
    })
    .map("NotAction")
    .flatten()
    .value();
}

function extractNotResources(statements) {
  return _.chain(statements)
    .filter(function(statement) {
      return statement.NotResource !== undefined;
    })
    .map("NotResource")
    .flatten()
    .value();
}

function extractStatements(object) {
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

function toWildcard(input) {
  if (input === undefined) {
    return "*";
  } else {
    return input;
  }
}

function toArray(input) {
  if (Array.isArray(input) === false) {
    return [input];
  } else {
    return input;
  }
}

function cross(action, resource) {
  var res = [];
  _.each(toArray(toWildcard(action)), function(a) {
    _.each(toArray(toWildcard(resource)), function(r) {
      res.push({"action": a, "resource": r});
    });
  });
  return res;
}
exports.cross = cross;

function extractAllowedActionResourcePairs(statements) {
  return _.chain(statements)
    .filter(filterEffectAllow)
    .map(function(statement) {
      return cross(statement.Action, statement.Resource);
    })
    .flatten()
    .value();
}

exports.check = function(objects, options, cb) {
  var findings = [];
  function checker(object) {
    var statements = extractStatements(object);
    var notActions = extractNotActions(statements);
    var notResources = extractNotResources(statements);
    var allowedActionResourcePairs = extractAllowedActionResourcePairs(statements);
    if (notActions.length > 0) {
      _.each(notActions, function(action) {
        findings.push({
          logicalID: object.LogicalId,
          message: "NotAction " + action + " is not allowed"
        });
      });
    } else if (notResources.length > 0) {
      _.each(notResources, function(resource) {
        findings.push({
          logicalID: object.LogicalId,
          message: "NotResource " + resource + " is not allowed"
        });
      });
    } else {
      _.each(allowedActionResourcePairs, function(pair) {
        if (_.some(options.allow, function(allow) {
          return _.some(toArray(toWildcard(allow.action)), function(allowAction) {
            return wildstring.match(allowAction, pair.action);
          }) && _.some(toArray(toWildcard(allow.resource)), function(allowResource) {
            return wildstring.match(allowResource, pair.resource);
          });
        }) === false) {
          findings.push({
            logicalID: object.LogicalId,
            message: "Action & Resource " + pair.action + " & " + pair.resource + " not allowed"
          });
        }
        if (_.some(options.deny, function(deny) {
          return _.some(toArray(toWildcard(deny.action)), function(denyAction) {
            return wildstring.match(denyAction, pair.action);
          }) && _.some(toArray(toWildcard(deny.resource)), function(denyResource) {
            return wildstring.match(denyResource, pair.resource);
          });
        }) === true) {
          findings.push({
            logicalID: object.LogicalId,
            message: "Action & Resource " + pair.action + " & " + pair.resource + " denied"
          });
        }
      });
    }
  }
  _.chain(objects)
    .filter(filterPartResource)
    .filter(filterTypeIamEntity)
    .each(checker)
    .value();
  cb(null, findings);
};
