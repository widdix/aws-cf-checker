# AWS CloudFormation Checker

## Installation

```
npm install cf-checker
```

## CLI Usage

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
