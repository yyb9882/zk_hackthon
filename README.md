# Table of Contents
* Category1 (this is the folder that we made to deliver the solution for Task1.1): 
  * 1 `test`: Test the correctness of SHA256 implementation.
    * 1.1 `circuits`: Verification circuits. 
      * 1.1.1 `SHA256_1.circom`: Verification circuit for SHA256('abc').
      * 1.1.2 `SHA256_2.circom`: Verification circuit for SHA256('abc...abc') ('abc' repeated 24 times).
    * 1.2 `SHA256_1.js`: Mocha Test for SHA256('abc') corresponding to `SHA256_1.circom`.
    * 1.3 `SHA256_2.js`: Mocha Test for SHA256('abc...abc') ('abc' repeated 24 times) corresponding to `SHA256_2.circom`. 
  * 2 `constants.circom`: Constants used in SHA256.
  * 3 `gadgets.circom`: All subcomputation and utilities used in SHA256.
  * 4 `sha256.circom`: SHA256 main function, including SHA256 hash function, padding and SHA256 compression function.
  * 5 `Demonstration.mp4`: Demonstration of our SHA256 hash function submission.
  * 6 `README.md`: Guidance for testing our SHA256 implementation.
* Category4 (this is the folder that we made to deliver the solution for Task 4.2):
  * 1
  * 2
  * 3
# Build and Run Guide

Please go to [category1](https://github.com/yyb9882/zk_hackthon/tree/main/category1) and [category4](https://github.com/yyb9882/zk_hackthon/tree/main/category4/zk-mooc-halo2) for the specifications.

# Description of optimization

Please go to [category1](https://github.com/yyb9882/zk_hackthon/tree/main/category1) and [category4](https://github.com/yyb9882/zk_hackthon/tree/main/category4/zk-mooc-halo2) for details.
