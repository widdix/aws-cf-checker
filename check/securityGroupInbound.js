/*
Checks that only security groups attached to:

* AWS::ElasticLoadBalancing::LoadBalancer (external)

allow traffic from public IP addresses.

Security groups attached to:

* AWS::ElasticLoadBalancing::LoadBalancer (internal)
* AWS::AutoScaling::LaunchConfiguration
* AWS::EC2::NetworkInterface
* AWS::EC2::Instance
* AWS::EC2::SpotFleet
* AWS::RDS::DBInstance
* AWS::RDS::DBCluster
* AWS::Redshift::Cluster
* AWS::ElastiCache::CacheCluster
* AWS::ElastiCache::ReplicationGroup
* AWS::EFS::MountTarget
* AWS::OpsWorks::Layer

should only allow inbound traffic from other security groups or private ip addresses.

Assumes that your account only supports the [EC2 platform](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-supported-platforms.html) EC2-VPC.

Options: (Object)

none
*/

// TODO what about port ranges? I think we should not allow them
// TODO it should be possible to allow or deny ports in the options
"use strict";

var _ = require("lodash");
var privateIpRange = require("../lib/privateIpRange.js");

function filterPartResource(object) {
  return object.Part === "Resource";
}

function filterTypeSecurityGroup(object) {
  return object.Type === "AWS::EC2::SecurityGroup";
}

function filterTypeSecurityGroupIngress(object) {
  return object.Type === "AWS::EC2::SecurityGroupIngress";
}

function mapRef(entry) {
  return entry.Ref;
}

function normalizeSecurityGroupAttachmentIds(propertyName) {
  return function(object) {
    if (object.Properties[propertyName] === undefined) {
      throw new Error("can not find property " + propertyName + " in " + object.LogicalId);
    }
    return _.map(object.Properties[propertyName], mapRef);
  };
}

function alwaysPrivate(object) {
  return false;
}

// defines what types can be attached to a security group
var SECURITY_GROUP_ATTACHMENT_DEFINITION = {
  "AWS::ElasticLoadBalancing::LoadBalancer": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("SecurityGroups"),
    "isPublicFun": function(object) {
      if(object.Properties.Scheme === "internal") {
        return false;
      }
      return true;
    }
  },
  "AWS::AutoScaling::LaunchConfiguration": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("SecurityGroups"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::RDS::DBInstance": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("VPCSecurityGroups"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::RDS::DBCluster": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("VpcSecurityGroupIds"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::Redshift::Cluster": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("VpcSecurityGroupIds"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::ElastiCache::CacheCluster": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("VpcSecurityGroupIds"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::ElastiCache::ReplicationGroup": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("SecurityGroupIds"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::EC2::Instance": {
    "normalizationFun": function(object) {
      if (object.Properties.NetworkInterfaces) {
        return _.chain(object.Properties.NetworkInterfaces)
          .map("GroupSet")
          .flatten()
          .map(mapRef)
          .value();
      } else {
        return normalizeSecurityGroupAttachmentIds("SecurityGroupIds")(object);
      }
    },
    "isPublicFun": alwaysPrivate // TODO is the assumption that a standalone EC2 instance should be never accessible from the outside valid?
  },
  "AWS::EFS::MountTarget": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("SecurityGroups"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::EC2::SpotFleet": {
    "normalizationFun": function(object) {
      return _.chain(object.Properties.SpotFleetRequestConfigData.LaunchSpecifications)
        .map("SecurityGroups")
        .flatten()
        .map(mapRef)
        .value();
    },
    "isPublicFun": alwaysPrivate
  },
  "AWS::OpsWorks::Layer": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("CustomSecurityGroupIds"),
    "isPublicFun": alwaysPrivate
  },
  "AWS::EC2::NetworkInterface": {
    "normalizationFun": normalizeSecurityGroupAttachmentIds("GroupSet"),
    "isPublicFun": alwaysPrivate // TODO is the assumption that a standalone ENI should be never accessible from the outside valid?
  }
};

function findSecurityGroupAttachments(objects, securityGroupObject) {
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
  return _.chain(attachments)
    .find(function(attachment) {
      var definition = SECURITY_GROUP_ATTACHMENT_DEFINITION[attachment.Type];
      return definition.isPublicFun(attachment);
    })
    .value() !== undefined;
}

function hasPrivateAttachments(attachments) {
  return _.chain(attachments)
    .find(function(attachment) {
      var definition = SECURITY_GROUP_ATTACHMENT_DEFINITION[attachment.Type];
      return !definition.isPublicFun(attachment);
    })
    .value() !== undefined;
}

function hasPublicRules(rules) {
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
