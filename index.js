"use strict";

var fs = require("fs");
var _ = require("lodash");
var async = require("neo-async");

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
  async.map(Object.keys(checks), function(check, cb) {
    var required;
    try {
      required = require("./check/" + check + ".js");
    } catch (err) {
      cb(err);
      return;
    }
    required.check(objects, checks[check], function(err, findings) {
      if (err) {
        cb(err);
      } else {
        cb(null, findings);
      }
    });
  }, function(err, nestedFindings) {
    if (err) {
      cb(err);
    } else {
      cb(null, _.flatten(nestedFindings));
    }
  });
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
