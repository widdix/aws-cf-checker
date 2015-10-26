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
});
