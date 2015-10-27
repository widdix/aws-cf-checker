// TODO what about SourceSecurityGroupName parameter for ec2 classic? should be disallowed?
// TODO what about port ranges? I think we should not allow them

var _ = require("lodash");
var privateIpRange = require("./privateIpRange.js");

function filterPartResource(object) {
  "use strict";
  return object.Part === "Resource";
}

function filterTypeSecurityGroup(object) {
  "use strict";
  return object.Type === "AWS::EC2::SecurityGroup";
}

function filterTypeSecurityGroupIngress(object) {
  "use strict";
  return object.Type === "AWS::EC2::SecurityGroupIngress";
}

function normalizeSecurityGroupAttachmentIds(propertyName) {
  "use strict";
  return function(object) {
    if (object.Properties[propertyName] === undefined) {
      throw new Error("can not find property " + propertyName + " in " + object.LogicalId);
    }
    return _.map(object.Properties[propertyName], "Ref");
  };
}

// defines what types can be attached to a security group
var SECURITY_GROUP_ATTACHMENT_DEFINITION = {
  "AWS::ElasticLoadBalancing::LoadBalancer": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("SecurityGroups"),
    "isPublicFun": function(object) {
      "use strict";
      if(object.Properties.Scheme === "internal") {
        return false;
      }
      return true;
    }
  },
  "AWS::AutoScaling::LaunchConfiguration": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("SecurityGroups"),
    "isPublicFun": function(object) {
      "use strict";
      return false;
    }
  },
  "AWS::RDS::DBInstance": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("VPCSecurityGroups"),
    "isPublicFun": function(object) {
      "use strict";
      return false; // TODO improve
    }
  }
};

function findSecurityGroupAttachments(objects, securityGroupObject) {
  "use strict";
  return _.chain(objects)
    .filter(filterPartResource)
    .filter(function(object) {
      var definition = SECURITY_GROUP_ATTACHMENT_DEFINITION[object.Type];
      return definition !== undefined;
    })
    .map(function(object) {
      var definition = SECURITY_GROUP_ATTACHMENT_DEFINITION[object.Type];
      object.AttachedSecurityGroupLogicalIds = definition.normalizationFun(object);
      return object;
    })
    .filter(function(object) {
      return object.AttachedSecurityGroupLogicalIds.indexOf(securityGroupObject.LogicalId) !== -1;
    })
    .value();
}

function extractIngressRules(objects, securityGroupObject) {
  "use strict";
  return _.chain(objects)
    .filter(filterPartResource)
    .filter(filterTypeSecurityGroupIngress)
    .filter(function(ingressObject) {
      if (ingressObject.Properties.GroupId.Ref === undefined) {
        return false;
      }
      return ingressObject.Properties.GroupId.Ref === securityGroupObject.LogicalId;
    })
    .value();
}

function hasPublicAttachments(attachments) {
  "use strict";
  return _.chain(attachments)
    .find(function(attachment) {
      var definition = SECURITY_GROUP_ATTACHMENT_DEFINITION[attachment.Type];
      return definition.isPublicFun(attachment);
    })
    .value() !== undefined;
}

function hasPrivateAttachments(attachments) {
  "use strict";
  return _.chain(attachments)
    .find(function(attachment) {
      var definition = SECURITY_GROUP_ATTACHMENT_DEFINITION[attachment.Type];
      return !definition.isPublicFun(attachment);
    })
    .value() !== undefined;
}

function hasPublicRules(rules) {
  "use strict";
  return _.chain(rules)
    .find(function(rule) {
      if (rule.CidrIp !== undefined) {
        return !privateIpRange(rule.CidrIp);
      }
      return false;
    })
    .value() !== undefined;
}

function hasPrivateRules(rules) {
  "use strict";
  return _.chain(rules)
    .find(function(rule) {
      if (rule.SourceSecurityGroupId !== undefined) {
        return true;
      }
      return privateIpRange(rule.CidrIp);
    })
    .value() !== undefined;
}

exports.check = function(objects, options, cb) {
  "use strict";
  var findings = [];
  function checker(object) {
    var rules = extractIngressRules(objects, object);
    rules = rules.concat(object.Properties.SecurityGroupIngress);
    var attachments = findSecurityGroupAttachments(objects, object);
    if (hasPublicAttachments(attachments) && hasPublicRules(rules)) {
      return;
    } else if (hasPublicAttachments(attachments) && hasPrivateRules(rules)) {
      return;
    } else if (hasPrivateAttachments(attachments) && hasPublicRules(rules)) {
      findings.push({
        logicalID: object.LogicalId,
        message: "public inbound rules for private attachments found"
      });
    } else if (hasPrivateAttachments(attachments) && hasPrivateRules(rules)) {
      return;
    } else {
      throw new Error("unexpected combination");
    }
  }
  _.chain(objects)
    .filter(filterPartResource)
    .filter(filterTypeSecurityGroup)
    .each(checker)
    .value();
  cb(null, findings);
};
