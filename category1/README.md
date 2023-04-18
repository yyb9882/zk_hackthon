<h1 align="center">SHA256 Circom Instantiation</h1>

## Overview

For some function, we refer to the circom library 

## Installation
1. Circom 
2. Install mocha test runner

## Build
```sh
circom test/circuits/SHA256_1.circom --r1cs
circom test/circuits/SHA256_2.circom --r1cs
```
Print the number of R1CS constraints

## Test the correctness of SHA256 circuit
```sh
mocha test --timeout 10000
```

## Comparison
We compare the number of R1CS constraints for the state-of-the-art work
