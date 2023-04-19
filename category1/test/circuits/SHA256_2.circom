pragma circom 2.0.0;
include "../../sha256.circom";
// compute hash of "abc" repetition for 3 * 8 times without padding 
// Input bits: 24 * 3 * 8
component main = sha256(24 * 3 * 8);