[![Build Status](https://secure.travis-ci.org/widdix/aws-cf-checker.png)](http://travis-ci.org/widdix/aws-cf-checker)
[![NPM version](https://badge.fury.io/js/aws-cf-checker.png)](http://badge.fury.io/js/aws-cf-checker)
[![NPM dependencies](https://david-dm.org/widdix/aws-cf-checker.png)](https://david-dm.org/widdix/aws-cf-checker)

# AWS CloudFormation Checker

## CLI usage

install

```
npm install cf-checker -g
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

## Checks

### logicalID

Checks logical ids of your template.

Options:

* `case`: Enum["pascal", "camel"]

### resourceType

Checks if the resource types are allowed in the template.

Options:

* `deny`: Array[String]
* `allow`: Array[String]

### securityGroupInbound

Checks that only security groups attached to external load balancers allow traffic from public internet.

Options:

(none)
