pragma circom 2.0.0;
include "../../sha256.circom";
// test for 'abc' with non-padding
// the binary representation of 'abc' is 24
component main = sha256(24);