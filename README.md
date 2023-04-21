# Table of Contents
* category1: 
  * 1
  * 2
  * 3
* category4:
  * 1
  * 2
  * 3
* Build and Run Guide
Please go to category1 and category2 for the specifications.

* Description of your implementation/optimization
## SHA256 Test
For more details about testing our SHA256 circom implementation, we refer you to [here](https://github.com/yyb9882/zk_hackthon/tree/main/category1).

## SHA256 Workflow
Template `sha256(l)` in `category1/SHA256.circom` is the main function for the entire SHA256 hash function (including padding and SHA256 compression function).
The workflow of SHA256 hash function is as follows:
  
1. Represent the message as binary string. (For a sake of time limitation, we do not consider message representation. Instead, the input message should be binary strings)
2. Padding the binary string(template `padding(l)` in `category1/SHA256.circom`) 
3. Split the padded binary string into several chunks, each chunk consists of 512 bits.
4. For each chunk, run a SHA256 compression function(template `sha256_compression` in `category1/SHA256.circom`).
5. Output the final state as the output of SHA256 hash function.
  
The total number of R1CS constraints is linear to the number of times to execute the SHA256 compression function.

## SHA256 Subcomputation
All the implementation of subcomputation (subcircuits) are implemented in `category1/gadgets.circom`,
most subcomputations are based on bit operations and we introduce it as follows:
### bitAND, bitXOR, bitNOT
It is unnecessary to verify every input lies in the binary field (0 or 1), which significantly reduce the number of R1CS constraints.
All bits will be checked in some intermediate rounds and in the final round.
### SmallSigma, BigSigma
$$SmallSigma(ra, rb, rc)\ =\ RightRotate(a, ra)\oplus{RightRotate(b, rb)}\oplus{RightShift(c, rc)}$$ 
  
$$BigSigma(ra, rb, rc)\ =\ RightRotate(a, ra)\oplus{RightRotate(b, rb)}\oplus{RightRotate(c, rc)}$$ 
We use the same implementation of these two subcomputations in [here](https://github.com/iden3/circomlib/blob/master/circuits/sha256/sigma.circom).
### Maj, Ch
$$maj(a,b,c) = (a\ and\ b) \oplus (a\ and\ c) \oplus (b\ and\ c)$$
  
$$ch(e,f,g) = (e\ and\ f) \oplus ((not\ e)\ and\ g)$$
We use the same implementation of maj operation in [here](https://github.com/iden3/circomlib/blob/master/circuits/sha256/maj.circom) and ch operation in [here](https://github.com/iden3/circomlib/blob/master/circuits/sha256/ch.circom).
### bitADD
bitADD operation is used to add two binary strings and then modulo $2^{32}$. The highest bit is not needed if it exceeds $2^{32}$.
With the same reason as mentioned in bitAND operations, most intermediate bits need not be checked in order to reduce the number of R1CS constraints.

## Comparison
We compare the number of R1CS constraints for the state-of-the-art work:
| Example | Description | Number of constraints |
| ----- | --- | --- |
| [xjsnark SHA-256 (Unpadded)](https://github.com/akosba/xjsnark/tree/master/doc/code_previews/README.md#sha-256-unpadded) |  High-level implementation of SHA-256 which is compiled to an optimized circuit similar to the one produced by manual/low-level libraries, as in [jsnark](https://github.com/akosba/jsnark). One round compression| 25538 | 
| [Ours (1 compression)] [here](https://github.com/yyb9882/zk_hackthon/blob/main/category1/test/circuits/SHA256_1.circom) | One chunk (only need 1 round compression) | 21488 |
| [Ours (2 compression)] [here](https://github.com/yyb9882/zk_hackthon/blob/main/category1/test/circuits/SHA256_2.circom) | Two chunks (needs 2 round compression) | 42976 


<h1 align="center">Category 4: Halo2 -- Blake2 Hash Function Instantiation</h1>
