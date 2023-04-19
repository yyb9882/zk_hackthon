<h1 align="center">SHA256 Circom Instantiation</h1>

## Overview
This is a SHA256 circuit instantiation for zk hackthon. Our team uses circom to instantiate the entire SHA256 hash function.
The structure of our project is described as follows:
1. `sha256.circom`: main function for sha256 circuit, including padding and SHA256 compression function.
2. `gadgets.circom`: all subcircuit used in SHA256 compression function.
3. `constants.circom`: constants k and H used in SHA256 compression function.
4. `test/circuits/SHA256_1.circom`: test for the correctness of SHA256('abc').
5. `test/circuits/SHA256_2.circom`: test for the correctness of SHA256('abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc').

## Installation
1. Install `circom` following this [installation guide](https://docs.circom.io/getting-started/installation/). Once installed, ensure that you're using the correct version of `circom` by running `circom --version`. You should see `circom compiler 2.1.4` or later.
2. Install the `mocha test runner`: run `npm install -g mocha`.
3. Run `mocha test` and verify that most of the tests fail, but not because of missing dependencies.

## Build
With the number of chunks in SHA256 hash function increases, 
To print the number of R1CS constraints, run the following commands:
```sh
circom test/circuits/SHA256_1.circom --r1cs
circom test/circuits/SHA256_2.circom --r1cs
```
It is obvious that the number of R1CS constraints of the entire SHA256 hash function is linear to the number of chunks.
This is because the number of times to execute the SHA256 compression function is equal to the number of chunks.

## Verify the Correctness of SHA256 Circuit
You can run both of the tests with the command:
```sh
mocha test --timeout 10000
```
or, you can run one of the two tests with the command:
```sh
mocha test/SHA256_1 --timeout 10000
mocha test/SHA256_2 --timeout 10000
```

## Comparison
We compare the number of R1CS constraints for the state-of-the-art work:
| Example ([previews](https://github.com/akosba/xjsnark/tree/master/doc/code_previews#code-previews)) | Description | Number of constraints |
| ----- | --- | --- |
| [SHA-256 (Unpadded)](https://github.com/akosba/xjsnark/tree/master/doc/code_previews/README.md#sha-256-unpadded) |  High-level implementation of SHA-256 which is compiled to an optimized circuit similar to the one produced by manual/low-level libraries, as in [jsnark](https://github.com/akosba/jsnark). | 25538 | 
| Ours | -- | --
