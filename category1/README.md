<h1 align="center">SHA256 Circom Instantiation</h1>

## Overview

For some function, we refer to the circom library 

## Installation

## Build
```sh
circom test/circuits/SHA256_1.circom --r1cs
circom test/circuits/SHA256_2.circom --r1cs
```
## Test the correctness of SHA256 circuit
```sh
mocha test --timeout 10000
```

## Comparison
