pragma circom 2.0.0;

/*
 * Outputs `x` AND `y`
 */
template bitAnd()
{
    signal input x[32];
    signal input y[32];
    signal output out[32];
    for(var i = 0; i < 32; i++)
    {
        out[i] <== x[i] * y[i];
        // out[i] * (1 - out[i]) === 0;
    }
}

/*
 * Outputs `x` XOR `y`
 * out = x + y - 2xy
 */
template bitXOR()
{
    signal input x[32];
    signal input y[32];
    signal output out[32];
    // XOR
    for(var i = 0; i < 32; i++)
    {
        out[i] <== x[i] + y[i] - 2 * x[i] * y[i];
        // out[i] * (1 - out[i]) === 0;
    }
}

/*
 * Outputs NOT `x`
 * out = 1 - x
 */
template bitNOT()
{
    signal input x[32];
    signal output out[32];
    // NOT
    for(var i = 0; i < 32; i++)
    {
        out[i] <== 1 - x[i];
        // out[i] * (1 - out[i]) === 0;
    }
}

/*
 * split gate
 * Decomposes `in` into `b` bits, given by `bits`.
 * Least significant bit in `bits[0]`.
 * Enforces that `in` is at most `b` bits long.
 */
template Num2Bits(b) {
    signal input in;
    signal output bits[b];

    for (var i = 0; i < b; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (1 - bits[i]) === 0;
    }
    var sum_of_bits = 0;
    for (var i = 0; i < b; i++) {
        sum_of_bits += (2 ** i) * bits[i];
    }
    sum_of_bits === in * 1;
}

/*
 * split gate
 * Decomposes `in` into `b` bits, given by `bits`.
 * Least significant bit in `bits[0]`.
 * Enforces that `in` is at most `b` bits long.
 */
template Num2BitsWithoutConstraints(b) {
    signal input in;
    signal output bits[b];

    for (var i = 0; i < b; i++) {
        bits[i] <-- (in >> i) & 1;
        // bits[i] * (1 - bits[i]) === 0;
    }
    // var sum_of_bits = 0;
    // for (var i = 0; i < b; i++) {
    //     sum_of_bits += (2 ** i) * bits[i];
    // }
    // sum_of_bits === in * 1;
}

/*
 * pack gate
 * Reconstructs `out` from `b` bits, given by `bits`.
 * Least significant bit in `bits[0]`.
 */
template Bits2Num(b) {
    signal input bits[b];
    signal output out;
    var lc = 0;

    for (var i = 0; i < b; i++) {
        lc += (bits[i] * (1 << i));
    }
    out <== lc;
}

/*
 * Modular addition for 2^32 (with carry)
 * For use
*/
template bitADD()
{
    // check the correctness of this
    // signal input x_tmp, y_tmp;
    // signal output out_tmp;
    signal input x[32], y[32];
    signal output out[32];
    // component x_and = Num2Bits(32);
    // x_and.in <-- x_tmp;
    // x <-- x_and.bits;
    // component y_and = Num2Bits(32);
    // y_and.in <-- y_tmp;
    // y <-- y_and.bits;
    // begin of workflow
    var carry = 0, tmp = 0;
    for(var i = 0; i < 32; i++)
    {
        tmp = x[i] + y[i] + carry;
        if (tmp == 0)
        {
            if (carry >= 1)
            {
                carry = carry - 1;
            }
        }
        else if (tmp == 1)
        {
            if (carry >= 1)
            {
                carry = carry - 1;
            }
        }
        else if (tmp == 2)
        {
            tmp = 0;
            carry = 1;
        }
        else if (tmp == 3)
        {
            tmp = 1;
            carry = 1;
        }
        out[i] <-- tmp;
        // out[i] * (1 - out[i]) === 0;
    }
    // end of workflow
    // check the correctness of this
    // component pack = Bits2Num(32);
    // pack.bits <-- out;
    // out_tmp <-- pack.out;
}

/*
 * Modular addition for 2^32 (with carry)
 * For use
*/
template bitADDwithOutput()
{
    // check the correctness of this
    // signal input x_tmp, y_tmp;
    signal output out_tmp;
    signal input x[32], y[32];
    signal out[32];
    // component x_and = Num2Bits(32);
    // x_and.in <-- x_tmp;
    // x <-- x_and.bits;
    // component y_and = Num2Bits(32);
    // y_and.in <-- y_tmp;
    // y <-- y_and.bits;
    // begin of workflow
    var carry = 0, tmp = 0;
    for(var i = 0; i < 32; i++)
    {
        tmp = x[i] + y[i] + carry;
        if (tmp == 0)
        {
            if (carry >= 1)
            {
                carry = carry - 1;
            }
        }
        else if (tmp == 1)
        {
            if (carry >= 1)
            {
                carry = carry - 1;
            }
        }
        else if (tmp == 2)
        {
            tmp = 0;
            carry = 1;
        }
        else if (tmp == 3)
        {
            tmp = 1;
            carry = 1;
        }
        out[i] <-- tmp;
        // out[i] * (1 - out[i]) === 0;
    }
    // end of workflow
    // check the correctness of this
    component pack = Bits2Num(32);
    pack.bits <-- out;
    out_tmp <-- pack.out;
}

/*
 * Modular addition for 2^32 (with carry)
 * Test for correctness
*/
template ADD()
{
    // check the correctness of this
    signal input x_tmp, y_tmp;
    signal output out_tmp;
    signal x[32],y[32];
    signal out[32];
    component x_and = Num2Bits(32);
    x_and.in <-- x_tmp;
    x <-- x_and.bits;
    component y_and = Num2Bits(32);
    y_and.in <-- y_tmp;
    y <-- y_and.bits;
    // begin of workflow
    var carry = 0, tmp = 0;
    for(var i = 0; i < 32; i++)
    {
        tmp = x[i] + y[i] + carry;
        if (tmp == 0)
        {
            if (carry >= 1)
            {
                carry = carry - 1;
            }
        }
        else if (tmp == 1)
        {
            if (carry >= 1)
            {
                carry = carry - 1;
            }
        }
        else if (tmp == 2)
        {
            tmp = 0;
            carry = 1;
        }
        else if (tmp == 3)
        {
            tmp = 1;
            carry = 1;
        }
        out[i] <-- tmp;
        out[i] * (1 - out[i]) === 0;
    }
    // end of workflow
    // check the correctness of this
    component pack = Bits2Num(32);
    pack.bits <-- out;
    out_tmp <-- pack.out;
}

/* Compute ch
 * 
 */
template getCh()
{
    signal input e[32],f[32],g[32];
    signal output ch[32];
    for (var i = 0; i < 32; i++)
    {
        ch[i] <== e[i] * (f[i] - g[i]) + g[i];
    }
}

/* Compute Maj
 * 
 */
template getMaj()
{
    signal input a[32],b[32],c[32];
    signal output maj[32];
    signal mid[32];
    signal output out;
    for (var i = 0; i < 32; i++)
    {
        mid[i] <== b[i] * c[i];
        maj[i] <== a[i] * (b[i] + c[i]- 2 * mid[i]) + mid[i];
    }
    // test the result is true or false
    // component maj_out = Bits2Num(32);
    // maj_out.bits <-- maj;
    // out <-- maj_out.out;
}

// Copied from circom library
template RotR(r) {
    signal input in[32];
    signal output out[32];

    for (var i=0; i<32; i++) {
        out[i] <== in[ (i+r)%32 ];
    }
}

template ShR(r) {
    signal input in[32];
    signal output out[32];

    for (var i=0; i<32; i++) {
        if (i+r >= 32) {
            out[i] <== 0;
        } else {
            out[i] <== in[ i+r ];
        }
    }
}

template Xor3() {
    signal input a[32];
    signal input b[32];
    signal input c[32];
    signal output out[32];
    signal mid[32];

    for (var k=0; k<32; k++) {
        mid[k] <== b[k] * c[k];
        out[k] <== a[k] * (1 -2*b[k]  -2*c[k] +4*mid[k]) + b[k] + c[k] -2*mid[k];
    }
}



template SmallSigma(ra, rb, rc) {
    signal input in[32];
    signal output out[32];
    var k;

    component rota = RotR(ra);
    component rotb = RotR(rb);
    component shrc = ShR(rc);

    for (k=0; k<32; k++) {
        rota.in[k] <== in[k];
        rotb.in[k] <== in[k];
        shrc.in[k] <== in[k];
    }

    component xor3 = Xor3();
    for (k=0; k<32; k++) {
        xor3.a[k] <== rota.out[k];
        xor3.b[k] <== rotb.out[k];
        xor3.c[k] <== shrc.out[k];
    }

    for (k=0; k<32; k++) {
        out[k] <== xor3.out[k];
    }
}

template BigSigma(ra, rb, rc) {
    signal input in[32];
    signal output out[32];
    var k;

    component rota = RotR(ra);
    component rotb = RotR(rb);
    component rotc = RotR(rc);
    for (k=0; k<32; k++) {
        rota.in[k] <== in[k];
        rotb.in[k] <== in[k];
        rotc.in[k] <== in[k];
    }

    component xor3 = Xor3();

    for (k=0; k<32; k++) {
        xor3.a[k] <== rota.out[k];
        xor3.b[k] <== rotb.out[k];
        xor3.c[k] <== rotc.out[k];
    }

    for (k=0; k<32; k++) {
        out[k] <== xor3.out[k];
    }
}

function nbits(a) {
    var n = 1;
    var r = 0;
    while (n-1<a) {
        r++;
        n *= 2;
    }
    return r;
}

template BinSum(n, ops) {
    var nout = nbits((2**n -1)*ops);
    signal input in[ops][n];
    signal output out[nout];

    var lin = 0;
    var lout = 0;

    var k;
    var j;

    var e2;

    e2 = 1;
    for (k=0; k<n; k++) {
        for (j=0; j<ops; j++) {
            lin += in[j][k] * e2;
        }
        e2 = e2 + e2;
    }

    e2 = 1;
    for (k=0; k<nout; k++) {
        out[k] <-- (lin >> k) & 1;

        // Ensure out is binary
        out[k] * (out[k] - 1) === 0;

        lout += out[k] * e2;

        e2 = e2+e2;
    }

    // Ensure the sum;

    lin === lout;
}