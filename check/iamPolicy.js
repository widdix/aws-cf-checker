/*
Checks allowed actions and resources of IAM policy statements. Wildcard * is supported.

A statement with NotAction is a finding.
A statement with Effect != Allow is skipped.

If you `deny` something, everything that is not denied is allowed.
If you `allow` something, everything that is not allowed is denied.

Options: (Object)

* `allow`: (Array[Object]) List of allowed actions & resources  (whitelist)
 * `action`: (String) IAM action (wildcard * can be used)
 * `resource`: (String) IAM resource (wildcard * can be used)
* `deny`: (Array[Object]) List of denied actions & resources (blacklist)
 * `action`: (String) IAM action (wildcard * can be used)
 * `resource`: (String) IAM resource (wildcard * can be used)
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

function cross(action, resource) {
  "use strict";
  if (action === undefined) {
    action = "*";
  } else if (typeof action === "string") {
    action = [action];
  }
  if (resource === undefined) {
    resource = "*";
  } else if (typeof resource === "string") {
    resource = [resource];
  }
  var res = [];
  _.each(action, function(a) {
    _.each(resource, function(r) {
      res.push({"action": a, "resource": r});
    });
  });
  return res;
}
exports.cross = cross;

function extractAllowedActionResourcePairs(statements) {
  "use strict";
  return _.chain(statements)
    .filter(filterEffectAllow)
    .map(function(statement) {
      return cross(statement.Action, statement.Resource);
    })
    .flatten()
    .value();
}

exports.check = function(objects, options, cb) {
  "use strict";
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
        if (options.allow !== undefined && _.some(options.allow, function(allow) {
          return wildstring.match(allow.action, pair.action) && wildstring.match(allow.resource, pair.resource);
        }) === false) {
          findings.push({
            logicalID: object.LogicalId,
            message: "Action & Resource " + pair.action + " & " + pair.resource + " not allowed"
          });
        }
        if (options.deny !== undefined && _.some(options.deny, function(deny) {
          return wildstring.match(deny.action, pair.action) && wildstring.match(deny.resource, pair.resource);
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
