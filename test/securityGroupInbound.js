"use strict";

var checker = require("../index.js");
var assert = require("assert-plus");

function test(template, options, expectedFindings, done) {
  checker.checkTemplate(template, options, function(err, findings) {
    if (err) {
      throw err;
    } else {
      assert.equal(findings.length, expectedFindings, "findings");
      done();
    }
  });
}

describe("securityGroupInbound", function() {
  it("empty", function(done) {
    test({

    }, {"securityGroupInbound": true}, 0, done);
  });
  it("secure AutoScaling + LoadBalancer setup", function(done) {
    test({
      "Resources": {
        "SGServer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "SourceSecurityGroupId": {"Ref": "SGLoadBalancer"}
            }]
          }
        },
        "SGLoadBalancer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "CidrIp": "0.0.0.0/0"
            }]
          }
        },
        "LoadBalancer": {
          "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGLoadBalancer"}]
          }
        },
        "AutoScalingGroup": {
          "Type": "AWS::AutoScaling::AutoScalingGroup",
          "Properties": {
            "LaunchConfigurationName": {"Ref": "LaunchConfiguration"},
            "LoadBalancerNames": [{"Ref": "LoadBalancer"}]
          }
        },
        "LaunchConfiguration": {
          "Type": "AWS::AutoScaling::LaunchConfiguration",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGServer"}]
          }
        }
      }
    }, {"securityGroupInbound": true}, 0, done);
  });
  it("secure AutoScaling + LoadBalancer + RDS instance setup", function(done) {
    test({
      "Resources": {
        "SGDatabase": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 3306,
              "ToPort": 3306,
              "IpProtocol": "tcp",
              "SourceSecurityGroupId": {"Ref": "SGServer"}
            }]
          }
        },
        "SGServer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "SourceSecurityGroupId": {"Ref": "SGLoadBalancer"}
            }]
          }
        },
        "SGLoadBalancer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "CidrIp": "0.0.0.0/0"
            }]
          }
        },
        "LoadBalancer": {
          "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGLoadBalancer"}]
          }
        },
        "AutoScalingGroup": {
          "Type": "AWS::AutoScaling::AutoScalingGroup",
          "Properties": {
            "LaunchConfigurationName": {"Ref": "LaunchConfiguration"},
            "LoadBalancerNames": [{"Ref": "LoadBalancer"}]
          }
        },
        "LaunchConfiguration": {
          "Type": "AWS::AutoScaling::LaunchConfiguration",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGServer"}]
          }
        },
        "Database": {
          "Type": "AWS::RDS::DBInstance",
          "Properties": {
            "VPCSecurityGroups": [{"Ref": "SGDatabase"}]
          }
        }
      }
    }, {"securityGroupInbound": true}, 0, done);
  });
  it("insecure AutoScaling + LoadBalancer setup", function(done) {
    test({
      "Resources": {
        "SGServer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "CidrIp": "0.0.0.0/0"
            }]
          }
        },
        "SGLoadBalancer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "CidrIp": "0.0.0.0/0"
            }]
          }
        },
        "LoadBalancer": {
          "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGLoadBalancer"}]
          }
        },
        "AutoScalingGroup": {
          "Type": "AWS::AutoScaling::AutoScalingGroup",
          "Properties": {
            "LaunchConfigurationName": {"Ref": "LaunchConfiguration"},
            "LoadBalancerNames": [{"Ref": "LoadBalancer"}]
          }
        },
        "LaunchConfiguration": {
          "Type": "AWS::AutoScaling::LaunchConfiguration",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGServer"}]
          }
        }
      }
    }, {"securityGroupInbound": true}, 1, done);
  });
  it("secure internal LoadBalancer setup", function(done) {
    test({
      "Resources": {
        "SGLoadBalancer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "CidrIp": "10.0.0.0/16"
            }]
          }
        },
        "LoadBalancer": {
          "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGLoadBalancer"}],
            "Scheme": "internal"
          }
        }
      }
    }, {"securityGroupInbound": true}, 0, done);
  });
  it("insecure internal LoadBalancer setup", function(done) {
    test({
      "Resources": {
        "SGLoadBalancer": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 80,
              "ToPort": 80,
              "IpProtocol": "tcp",
              "CidrIp": "0.0.0.0/0"
            }]
          }
        },
        "LoadBalancer": {
          "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
          "Properties": {
            "SecurityGroups": [{"Ref": "SGLoadBalancer"}],
            "Scheme": "internal"
          }
        }
      }
    }, {"securityGroupInbound": true}, 1, done);
  });
  it("secure RDS instance setup", function(done) {
    test({
      "Resources": {
        "SGDatabase": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 3306,
              "ToPort": 3306,
              "IpProtocol": "tcp",
              "CidrIp": "10.0.0.0/16"
            }]
          }
        },
        "Database": {
          "Type": "AWS::RDS::DBInstance",
          "Properties": {
            "VPCSecurityGroups": [{"Ref": "SGDatabase"}]
          }
        }
      }
    }, {"securityGroupInbound": true}, 0, done);
  });
  it("insecure RDS instance setup", function(done) {
    test({
      "Resources": {
        "SGDatabase": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 3306,
              "ToPort": 3306,
              "IpProtocol": "tcp",
              "CidrIp": "0.0.0.0/0"
            }]
          }
        },
        "Database": {
          "Type": "AWS::RDS::DBInstance",
          "Properties": {
            "VPCSecurityGroups": [{"Ref": "SGDatabase"}]
          }
        }
      }
    }, {"securityGroupInbound": true}, 1, done);
  });
  it("secure RDS instance setup with external security group", function(done) {
    test({
      "Parameters": {
        "SGDatabase": {
          "Type": "AWS::EC2::SecurityGroup::Id",
        }
      },
      "Resources": {
        "Database": {
          "Type": "AWS::RDS::DBInstance",
          "Properties": {
            "VPCSecurityGroups": [{"Ref": "SGDatabase"}]
          }
        }
      }
    }, {"securityGroupInbound": true}, 0, done);
  });
  it("secure RDS instance setup with external security group as source", function(done) {
    test({
      "Parameters": {
        "SGDatabaseClient": {
          "Type": "AWS::EC2::SecurityGroup::Id",
        }
      },
      "Resources": {
        "SGDatabase": {
          "Type": "AWS::EC2::SecurityGroup",
          "Properties": {
            "SecurityGroupIngress": [{
              "FromPort": 3306,
              "ToPort": 3306,
              "IpProtocol": "tcp",
              "SourceSecurityGroupId": {"Ref": "SGDatabaseClient"}
            }]
          }
        },
        "Database": {
          "Type": "AWS::RDS::DBInstance",
          "Properties": {
            "VPCSecurityGroups": [{"Ref": "SGDatabase"}]
          }
        }
      }
    }, {"securityGroupInbound": true}, 0, done);
  });
});
