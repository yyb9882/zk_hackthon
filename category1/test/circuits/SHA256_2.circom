pragma circom 2.0.0;
include "../../sha256.circom";
// compute hash of "abc" repetition for 3 * 6 times without padding 
// Input bits: 24 * 3 * 6
component main = sha256(24 * 3 * 6);