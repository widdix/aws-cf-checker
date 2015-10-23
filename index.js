var fs = require("fs");
var _ = require("underscore");

function loadJSONFile(filename, cb) {
  fs.readFile(filename, {"encoding": "utf8"}, cb);
}

function parseJSON(json, cb) {
  cb(null, JSON.parse(json));
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function mapTemplate(template, cb) {
  var objects = [];
  function mapper(part) {
    return function(object, logicalId) {
      var res = clone(object);
      res.LogicalId = logicalId;
      res.Part = part;
      return res;
    };
  }
  objects = objects.concat(_.map(template.Parameters, mapper("Parameter")));
  objects = objects.concat(_.map(template.Mappings, mapper("Mapping")));
  objects = objects.concat(_.map(template.Conditions, mapper("Condition")));
  objects = objects.concat(_.map(template.Resources, mapper("Resource")));
  objects = objects.concat(_.map(template.Outputs, mapper("Output")));
  cb(null, objects);
}

function runChecks(objects, checks, cb) {
  var findings = [];
  function checkCallback(err, checkFindings) {
    if (err) {
      return cb(err);
    } else {
      findings = findings.concat(checkFindings);
    }
  }
  for (var check in checks) {
    if (checks.hasOwnProperty(check)) {
      require("./lib/" + check + ".js").check(objects, checks[check], checkCallback);
    }
  }
  cb(null, findings);
}

function checkTemplate(template, checks, cb) {
  mapTemplate(template, function(err, objects) {
    if (err) {
      cb(err);
    } else {
      runChecks(objects, checks, cb);
    }
  });
}

exports.checkTemplate = checkTemplate;

exports.checkFile = function(filename, checks, cb) {
  loadJSONFile(filename, function(err, json) {
    if (err) {
      cb(err);
    } else {
      parseJSON(json, function(err, template) {
        if (err) {
          cb(err);
        } else {
          checkTemplate(template, checks, cb);
        }
      });
    }
  });
};
