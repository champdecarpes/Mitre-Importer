# Importer for Data of MITRE-ATTACK Matrices

--------------

## Getting started

### Prerequisites

- Install [Node.js]() which includes [Node Package Manager](https://www.npmjs.com/)

### Install

Package can be installed with the following commands: 
```
npm install mitre-importer
```
#### or
```
yarn add mitre-importer
```

### Usage 

```
import MitreMatrix from 'mitre-importer';

const Mitre = new MitreAttack('enterprise-attack');
const enterprise = Mitre.getDomainTable();
```
--------------

## Functionality

- You can pass **configs** for ***techniques*** and ***tactics*** when initializing a class object. By default configs are **[name, type]**
- You can use 

### Methods

`new MitreAttack( matrix, tacticConfig?, techniqueConfig?, siemData? )` - **Initial** class object

`.getTypeData( typeName, config? )` - Getting a list of the **selected type**

`.getTechniques()` - Getting a **techniques** with **sub-techniques** list in json format

`.getDomainTable()` - Getting a **full matrix** data

### Types of Mitre elements




