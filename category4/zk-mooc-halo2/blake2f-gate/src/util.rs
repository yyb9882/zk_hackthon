/// The sequence of bits representing a u64 in little-endian order.
///
/// # Panics
///
/// Panics if the expected length of the sequence `NUM_BITS` exceeds
/// 64.
pub fn i2lebsp<const NUM_BITS: usize>(int: u64) -> [bool; NUM_BITS] {
    /// Takes in an FnMut closure and returns a constant-length array with elements of
    /// type `Output`.
    fn gen_const_array<Output: Copy + Default, const LEN: usize>(
        closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        gen_const_array_with_default(Default::default(), closure)
    }

    fn gen_const_array_with_default<Output: Copy, const LEN: usize>(
        default_value: Output,
        closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        let mut ret: [Output; LEN] = [default_value; LEN];
        for (bit, val) in ret.iter_mut().zip((0..LEN).map(closure)) {
            *bit = val;
        }
        ret
    }

    assert!(NUM_BITS <= 64);
    gen_const_array(|mask: usize| (int & (1 << mask)) != 0)
}

// TODO: add test

pub fn u1282lebsp(v: u128) -> [bool; 128] {
    let mut out = [false; 128];

    for i in 0..128 {
        out[i] = (v & (1 << i)) != 0;
    }

    out
}

/// Returns the integer representation of a little-endian bit-array.
/// Panics if the number of bits exceeds 64.
pub fn lebs2ip<const K: usize>(bits: &[bool; K]) -> u64 {
    assert!(K <= 64);
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}

pub fn lebs2u128<const K: usize>(bits: &[bool; K]) -> u128 {
    assert!(K <= 128);
    bits.iter()
        .enumerate()
        .fold(0u128, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}

pub fn arb_lebs2u128(bits: &[bool]) -> u128 {
    assert!(bits.len() <= 128);
    bits.iter()
        .enumerate()
        .fold(0u128, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}

/// Helper function that interleaves a little-endian bit-array with zeros
/// in the odd indices. That is, it takes the array
///         [b_0, b_1, ..., b_n]
/// to
///         [b_0, 0, b_1, 0, ..., b_n, 0].
/// Panics if bit-array is longer than 16 bits.
pub fn spread_bits<const DENSE: usize, const SPREAD: usize>(
    bits: impl Into<[bool; DENSE]>,
) -> [bool; SPREAD] {
    assert_eq!(DENSE * 2, SPREAD);
    // assert!(DENSE <= 16);

    let bits: [bool; DENSE] = bits.into();
    let mut spread = [false; SPREAD];

    for (idx, bit) in bits.iter().enumerate() {
        spread[idx * 2] = *bit;
    }

    spread
}

/// Returns even bits in a bit-array
pub fn even_bits<const LEN: usize, const HALF: usize>(bits: [bool; LEN]) -> [bool; HALF] {
    assert_eq!(LEN % 2, 0);
    let mut even_bits = [false; HALF];
    for idx in 0..HALF {
        even_bits[idx] = bits[idx * 2]
    }
    even_bits
}

/// Returns odd bits in a bit-array
pub fn odd_bits<const LEN: usize, const HALF: usize>(bits: [bool; LEN]) -> [bool; HALF] {
    assert_eq!(LEN % 2, 0);
    let mut odd_bits = [false; HALF];
    for idx in 0..HALF {
        odd_bits[idx] = bits[idx * 2 + 1]
    }
    odd_bits
}

pub fn spread_odd_u128_from_xor(a: u64, b: u64) -> u128 {
    lebs2u128(&spread_odd_bits_from_xor(a, b))
}
pub fn spread_odd_u128_from_three_xor(a: u64, b: u64, c: u64) -> u128 {
    lebs2u128(&spread_odd_bits_from_three_xor(a, b, c))
}

// TODO: check unused
pub fn spread_even_u128_from_xor(a: u64, b: u64) -> u128 {
    lebs2u128(&spread_even_bits_from_xor(a, b))
}

pub fn spread_odd_bits_from_xor(a: u64, b: u64) -> [bool; 128] {
    spread_helper::<false>(a, b)
}

pub fn spread_odd_bits_from_three_xor(a: u64, b: u64, c: u64) -> [bool; 128] {
    spread_helper_three::<false>(a, b, c)
}

pub fn spread_even_bits_from_xor(a: u64, b: u64) -> [bool; 128] {
    spread_helper::<true>(a, b)
}

// TODO: add test
fn spread_helper<const GET_SPREAD_EVEN: bool>(a: u64, b: u64) -> [bool; 128] {
    let a = lebs2u128(&spread_bits::<64, 128>(i2lebsp(a)));
    let b = lebs2u128(&spread_bits::<64, 128>(i2lebsp(b)));

    let c = a + b;

    let c = u1282lebsp(c);

    let c:[bool; 64] = if GET_SPREAD_EVEN {
        even_bits(c)
    } else {
        odd_bits(c)
    };

    spread_bits::<64, 128>(c)
}

fn spread_helper_three<const GET_SPREAD_EVEN: bool>(a: u64, b: u64, c:u64) -> [bool; 128] {
    let a = lebs2u128(&spread_bits::<64, 128>(i2lebsp(a)));
    let b = lebs2u128(&spread_bits::<64, 128>(i2lebsp(b)));
    let c = lebs2u128(&spread_bits::<64, 128>(i2lebsp(c)));

    let c = a + b + c;

    let c = u1282lebsp(c);

    let c:[bool; 64] = if GET_SPREAD_EVEN {
        even_bits(c)
    } else {
        odd_bits(c)
    };

    spread_bits::<64, 128>(c)
}
