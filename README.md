[![Build Status](https://secure.travis-ci.org/widdix/aws-cf-checker.png)](http://travis-ci.org/widdix/aws-cf-checker)
[![NPM version](https://badge.fury.io/js/aws-cf-checker.png)](http://badge.fury.io/js/aws-cf-checker)
[![NPM dependencies](https://david-dm.org/widdix/aws-cf-checker.png)](https://david-dm.org/widdix/aws-cf-checker)

# AWS CloudFormation Checker

Checks can guarantee high security, reliability and conformity of your CloudFormation templates. We provide a set of default checks that you can use to validate your templates.

## CLI usage

install the module globally

```
npm install aws-cf-checker -g
```

reading template from file

```
cf-checker --templateFile ./path/to/template.json

cf-checker --templateFile ./path/to/template.json --checksFile ./path/to/checks.json
```

reading template from stdin

```
cat ./path/to/template.json | cf-checker

cat ./path/to/template.json | cf-checker --checksFile ./path/to/checks.json
```

as long as the exit code is `0` your template is fine

## Programatic usage

install the module locally

```
npm install aws-cf-checker
```

reading template from file

```javascript
var checker = require("aws-cf-checker")

checker.checkFile("./path/to/template.json", {"logicalID": {}}, function(err, findings) {
  if (err) {
    throw err;
  } else {
    if (findings.length > 0) {
      console.error("findings", findings);
    } else {
      console.log("no findings");
    }
  }
});
```

using a template object

```javascript
var checker = require("aws-cf-checker")

var template = {
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "minimal template"
};
checker.checkTemplate(template, {"logicalID": {}}, function(err, findings) {
  if (err) {
    throw err;
  } else {
    if (findings.length > 0) {
      console.error("findings", findings);
    } else {
      console.log("no findings");
    }
  }
});
```

as long as the `findings` array is empty your template is fine

## Checks

Checks are configured with a JSON file. Have a look at our [default checks](https://github.com/widdix/aws-cf-checker/blob/master/checks.json). 

### logicalID

Checks logical ids of your template.

Options: (Object)

* `case`: Enum["pascal", "camel"] (default: "pascal")

### resourceType

Checks if the resource types are allowed in the template.

If you `deny` something, everything that is not denied is allowed.
If you `allow` something, everything that is not allowed is denied.

Options: (Object)

* `deny`: Array[String]
* `allow`: Array[String]

### securityGroupInbound

Checks that only security groups attached to:

* AWS::ElasticLoadBalancing::LoadBalancer (external)

allow traffic from public ip addresses.

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

### iamInlinePolicy

Checks IAM Users, Groups and Roles for inline policies.

Options: (Boolean)

`true` := inline policies are allowed
`false` := inline policies are denied

### iamPolicy

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
