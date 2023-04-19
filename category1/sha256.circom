pragma circom 2.0.0;
include "gadgets.circom";
include "constants.circom";
// Complete version for SHA256
template sha256(l)
{
    signal input M[l]; // For l bits
    var K = 512 * 1 - l - 65;
    while (K < 0)
    {
        K = K + 512;
    }
    // padding: <original message of length L> 1 <K zeros> <L as 64 bit integer>
    var final_length = l + 1 + K + 64;
    signal padded_M[final_length];
    component pad = padding(l);
    pad.M <-- M;
    padded_M <-- pad.padded_M;
    // Allocate chunk
    var b = (final_length / 512);
    signal tmp_M[b][512];
    for(var i = 0; i < b; i++)
    {
        for(var j = 0; j < 512; j++)
        {
            tmp_M[i][j] <-- padded_M[512 * i + j];
        }
    }
    // First round
    component compression[1000];
    compression[0] = sha256_compression();
    for(var i = 0; i < 8; i++)
    {
        compression[0].H[i] <-- H(i);
    }
    compression[0].M <-- tmp_M[0];
    signal output final_hash[8];
    var i = 1;
    for(i = 1; i < b; i++)
    {
        compression[i] = sha256_compression();
        for(var j = 0; j < 8; j++)
        {
            compression[i].H[j] <-- compression[i-1].hash[j];
        }
        compression[i].M <-- tmp_M[i];
    }
    final_hash <-- compression[i-1].hash;

}

// Pad messages for SHA256
template padding(l)
{
    signal input M[l];
    // signal output chunk[b][16];
    var K = 512 * 1 - l - 65;
    while (K < 0)
    {
        K = K + 512;
    }
    // padding: <original message of length L> 1 <K zeros> <L as 64 bit integer>
    var final_length = l + 1 + K + 64;
    signal output padded_M[final_length];
    var i = 0;
    for (i = 0; i < l; i++)
    {
        padded_M[i] <-- M[i];
    }
    padded_M[i] <-- 1;
    i = i + 1;
    for(var j = 0; j < K; j++)
    {
        padded_M[i] <-- 0;
        i = i + 1;
    }
    // get the length for padding
    component len = Num2BitsWithoutConstraints(64);
    signal length[64];
    len.in <-- l;
    length <-- len.bits;
    for(var j = 63; j >= 0; j--)
    {
        padded_M[i] <-- length[j];
        i = i + 1;
    }
}

// SHA256 compression function
template sha256_compression()
{
    // init state
    signal input H[8];
    // message for each chunk
    signal input M[512];
    signal a[65];
    signal b[65];
    signal c[65];
    signal d[65];
    signal e[65];
    signal f[65];
    signal g[65];
    signal h[65];
    signal a_bits[65][32];
    signal b_bits[65][32];
    signal c_bits[65][32];
    signal d_bits[65][32];
    signal e_bits[65][32];
    signal f_bits[65][32];
    signal g_bits[65][32];
    signal h_bits[65][32];
    signal output hash[8];
    // Process the message in successive 512-bit chunks
    // Ignore: first only consider one-round compression function
    // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array


    // In itialize working variables to current hash value
    a[0] <-- H[0];
    b[0] <-- H[1];
    c[0] <-- H[2];
    d[0] <-- H[3];
    e[0] <-- H[4];
    f[0] <-- H[5];
    g[0] <-- H[6];
    h[0] <-- H[7];
    // Process to bits
    component a_Num2Bits = Num2BitsWithoutConstraints(32);
    a_Num2Bits.in <-- a[0];
    a_bits[0] <-- a_Num2Bits.bits;
    component b_Num2Bits = Num2BitsWithoutConstraints(32);
    b_Num2Bits.in <-- b[0];
    b_bits[0] <-- b_Num2Bits.bits;
    component c_Num2Bits = Num2BitsWithoutConstraints(32);
    c_Num2Bits.in <-- c[0];
    c_bits[0] <-- c_Num2Bits.bits;
    component d_Num2Bits = Num2BitsWithoutConstraints(32);
    d_Num2Bits.in <-- d[0];
    d_bits[0] <-- d_Num2Bits.bits;
    component e_Num2Bits = Num2BitsWithoutConstraints(32);
    e_Num2Bits.in <-- e[0];
    e_bits[0] <-- e_Num2Bits.bits;
    component f_Num2Bits = Num2BitsWithoutConstraints(32);
    f_Num2Bits.in <-- f[0];
    f_bits[0] <-- f_Num2Bits.bits;
    component g_Num2Bits = Num2BitsWithoutConstraints(32);
    g_Num2Bits.in <-- g[0];
    g_bits[0] <-- g_Num2Bits.bits;
    component h_Num2Bits = Num2BitsWithoutConstraints(32);
    h_Num2Bits.in <-- h[0];
    h_bits[0] <-- h_Num2Bits.bits;
    signal H_bits[8][32];
    component H_Num2Bits[8];
    for (var i = 0; i < 8; i++)
    {
        H_Num2Bits[i] = Num2BitsWithoutConstraints(32);
        H_Num2Bits[i].in <-- H[i];
        H_bits[i] <-- H_Num2Bits[i].bits;
    }
    signal k_bits[64][32];
    component k_Num2Bits[64];
    for (var i = 0; i < 64; i++)
    {
        k_Num2Bits[i] = Num2BitsWithoutConstraints(32);
        k_Num2Bits[i].in <-- k(i);
        k_bits[i] <-- k_Num2Bits[i].bits;
    }
    
    // Preprocessing phase (Schedule)
    // Schedule: 6144 (Rotate, Shift, Xor, Addition modulo 2^32)
    // signal w[64];
    // for (var i = 0; i < 16; i++)
    // {
    //     w[i] <-- M[i];
    // }
    signal w_bits[64][32];
    // component w_Num2Bits[64];
    for (var i = 0; i < 16; i++)
    {
        // w_Num2Bits[i] = Num2BitsWithoutConstraints(32);
        // w_Num2Bits[i].in <-- w[i];
        // w_bits[i] <-- w_Num2Bits[i].bits;
        for(var j = 0; j < 32; j++)
        {
            w_bits[i][31 - j] <-- M[32 * i + j];
        }
    }

    signal s0[48][32], s1[48][32];
    component ssigma_0[48], ssigma_1[48]; 
    component addition[1000];
    component addition1[1000];
    component additions[1000];
    var j = 0;
    var K = 0;
    for(var i = 16; i < 64; i++)
    {   
        // w[i] = (ssigma1(w[i-2]) + w[i-7] + ssigma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF;
        // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        ssigma_0[i-16] = SmallSigma(17,19,10);
        ssigma_0[i-16].in <== w_bits[i-2];
        s0[i-16] <-- ssigma_0[i-16].out;
        // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        ssigma_1[i-16] = SmallSigma(7,18,3);
        ssigma_1[i-16].in <== w_bits[i-15];
        s1[i-16] <-- ssigma_1[i-16].out;
        // w[i] <-- (w[i-16] + s0 + w[i-7] + s1) % (2 ** 32);
        // Binary sum for 4 numbers
        addition1[j] = BinSum(32,4);
        for (K=0; K<32; K++) {
            addition1[j].in[0][K] <== s1[i-16][K];
            addition1[j].in[1][K] <== w_bits[i-7][K];
            addition1[j].in[2][K] <== s0[i-16][K];
            addition1[j].in[3][K] <== w_bits[i-16][K];
        }
        // get the first 32 bits
        for (K=0; K<32; K++) {
            w_bits[i][K] <== addition1[j].out[K];
        }
        j = j + 1;
    }
    K = 0;

    // Compression function
    component S1_component[64];
    component S0_component[64];
    component ch_component[64];
    component maj_component[64];
    signal S1[64][32], S0[64][32], ch[64][32], maj[64][32], temp1[64][32], temp2[64][32];
    for (var i = 0; i < 64; i++)
    {
        // S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        S1_component[i] = BigSigma(6,11,25);
        S1_component[i].in <-- e_bits[i];
        S1[i] <-- S1_component[i].out;
        // ch := (e and f) xor ((not e) and g)
        ch_component[i] = getCh();
        ch_component[i].e <-- e_bits[i];
        ch_component[i].f <-- f_bits[i];
        ch_component[i].g <-- g_bits[i];
        ch[i] <-- ch_component[i].ch;
        // temp1 := h + S1 + ch + k[i] + w[i]
        // temp1 每次都基于mod 2^32 运算, 效率低下
        addition[j] = bitADD();
        addition[j].x <-- h_bits[i];
        addition[j].y <-- S1[i];
        j = j + 1;
        addition[j] = bitADD();
        addition[j].x <-- addition[j-1].out;
        addition[j].y <-- ch[i];
        j = j + 1;
        addition[j] = bitADD();
        addition[j].x <-- addition[j-1].out;
        addition[j].y <-- k_bits[i];
        j = j + 1;
        addition[j] = bitADD();
        addition[j].x <-- addition[j-1].out;
        addition[j].y <-- w_bits[i];
        temp1[i] <-- addition[j].out;
        j = j + 1;
        // S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        S0_component[i] = BigSigma(2,13,22);
        S0_component[i].in <-- a_bits[i];
        S0[i] <-- S0_component[i].out;
        // maj := (a and b) xor (a and c) xor (b and c)
        maj_component[i] = getMaj();
        maj_component[i].a <-- a_bits[i];
        maj_component[i].b <-- b_bits[i];
        maj_component[i].c <-- c_bits[i];
        maj[i] <-- maj_component[i].maj;
        // temp2 := S0 + maj
        addition[j] = bitADD();
        addition[j].x <-- S0[i];
        addition[j].y <-- maj[i];
        temp2[i] <-- addition[j].out;
        j = j + 1;
        // update status
        // h := g
        h_bits[i+1] <-- g_bits[i];
        // g := f
        g_bits[i+1] <-- f_bits[i];
        // f := e
        f_bits[i+1] <-- e_bits[i];
        // e := d + temp1
        addition[j] = bitADD();
        addition[j].x <-- d_bits[i];
        addition[j].y <-- temp1[i];
        e_bits[i+1] <-- addition[j].out;
        j = j + 1;
        // d := c
        d_bits[i+1] <-- c_bits[i];
        // c := b
        c_bits[i+1] <-- b_bits[i];
        // b := a
        b_bits[i+1] <-- a_bits[i];
        // a := temp1 + temp2
        addition[j] = bitADD();
        addition[j].x <-- temp1[i];
        addition[j].y <-- temp2[i];
        a_bits[i+1] <-- addition[j].out;
        j = j + 1;
    }
    // // Add the compressed chunk to the current hash value
    // // h_i = h_i + a_i
    // // H[0] = H[0] + a[64];
    // // H[1] = H[1] + b[64];
    // // H[2] = H[2] + c[64];
    // // H[3] = H[3] + d[64];
    // // H[4] = H[4] + e[64];
    // // H[5] = H[5] + f[64];
    // // H[6] = H[6] + g[64];
    // // H[7] = H[7] + h[64];

    signal final_hash[8];
    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[0];
    additions[K].y <-- a_bits[64];
    final_hash[0] <-- additions[K].out_tmp;
    K = K + 1;

    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[1];
    additions[K].y <-- b_bits[64];
    final_hash[1] <-- additions[K].out_tmp;
    K = K + 1;

    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[2];
    additions[K].y <-- c_bits[64];
    final_hash[2] <-- additions[K].out_tmp;
    K = K + 1;

    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[3];
    additions[K].y <-- d_bits[64];
    final_hash[3] <-- additions[K].out_tmp;
    K = K + 1;

    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[4];
    additions[K].y <-- e_bits[64];
    final_hash[4] <-- additions[K].out_tmp;
    K = K + 1;

    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[5];
    additions[K].y <-- f_bits[64];
    final_hash[5] <-- additions[K].out_tmp;
    K = K + 1;

    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[6];
    additions[K].y <-- g_bits[64];
    final_hash[6] <-- additions[K].out_tmp;
    K = K + 1;

    additions[K] = bitADDwithOutput();
    additions[K].x <-- H_bits[7];
    additions[K].y <-- h_bits[64];
    final_hash[7] <-- additions[K].out_tmp;
    K = K + 1;

    // output final hash value
    for(var i = 0; i < 8; i++)
    {
        hash[i] <-- final_hash[i];
    }
}