[![Build Status](https://secure.travis-ci.org/widdix/aws-cf-checker.png)](http://travis-ci.org/widdix/aws-cf-checker)
[![NPM version](https://badge.fury.io/js/aws-cf-checker.png)](http://badge.fury.io/js/aws-cf-checker)
[![NPM dependencies](https://david-dm.org/widdix/aws-cf-checker.png)](https://david-dm.org/widdix/aws-cf-checker)

# AWS CloudFormation Checker

## CLI Usage

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

Options:

* `case`: Enum["pascal", "camel"]

### resourceType

Options:

* `deny`: Array[String]
* `allow`: Array[String]

### securityGroupInbound

Options
