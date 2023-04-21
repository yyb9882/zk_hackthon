use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Error, Selector},
};
use halo2curves::{FieldExt, bn256::{self, Fr}};

use crate::{InitializedState, util::{spread_bits, i2lebsp, odd_bits, u1282lebsp}};
use crate::state::InnerState;
use crate::{
    state::{match_state_as_array, RoundWord},
};

use super::CompressionConfig;
use crate::MAX_ROUND;

pub const INIT_STATE_ROWS: usize = 49;
pub const VARS_PER_ROUND: usize = 16 * 4;
pub const ROWS_PER_ROUND: usize = VARS_PER_ROUND * 4;

const PRE_COMPUTED: [[usize; 16]; 10] = [
    [0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15],
    [14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3],
    [11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4],
    [7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8],
    [9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13],
    [2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9],
    [12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11],
    [13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10],
    [6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5],
    [10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0],
];

impl CompressionConfig {
    pub(super) fn assign_round(
        &self,
        region: &mut Region<'_, bn256::Fr>,
        init_state: InitializedState,
        rounds: Value<u64>,
        m: [Value<u64>; 16], //TODO: assigned bits?
    ) -> Result<InnerState, Error> {
        let lookup = &self.lookup;

        let assigned_m = init_state.m;
        let assigned_rounds = init_state.round;
        let init_state = init_state.state;

        let mut _rounds = 0;
        rounds.map(|r| {(_rounds=r); r});
        let rounds = _rounds as usize;
        assert!(rounds <= MAX_ROUND);

        assigned_rounds.value().assert_if_known(|&v| *v == Fr::from(rounds as u64));
        for i in 0..m.len() {
            assigned_m[i].value().zip(m[i]).assert_if_known(|&(a_m, m)| *a_m == Fr::from(m));
        }

        let columns = self.columns.clone();

        let row_offset = INIT_STATE_ROWS;

        let vs: [Value<u64>; 16] = match_state_as_array(init_state.clone())
            .into_iter()
            .map(|s| s.val.value_u64())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut last_state: [RoundWord; 16] = match_state_as_array(init_state.clone());
        let mut last_assign_round = None;

        // copy value from scheduler (round -1 just copy from scheduler)
        {
            let offset = row_offset;

            for i in 0..VARS_PER_ROUND {
                let j = i % vs.len();

                let row = offset + i * 4;

                // NOTE: don't need enable decompose u64 selector and copy dense & spread
                last_state[j] = last_state[j].copy_into_with_lookup(region, row, &columns, lookup)?;

                // TODO: enable selector
                let round = region.assign_advice_from_constant(
                    || "assign round 0",
                    self.columns.round,
                    row,
                    Fr::zero(),
                )?;
                last_assign_round = Some(round);

                region.assign_advice_from_constant(
                    || "assign s_round 1",
                    self.columns.s_round,
                    row,
                    Fr::one(),
                )?;
            }
        }

        let row_offset = row_offset + ROWS_PER_ROUND;

        for r in 0..MAX_ROUND {
            let offset = row_offset + r * ROWS_PER_ROUND;

            if r < rounds {
                // TODO: enable selector
                // TODO: set && copy m

                // state is init state
                for sub_round in 1..=4 {
                    // TODO: asssgin odds_evens carefully
                    let (new_state, carry, odds_evens) = calc_round_state(vs, m, r, sub_round);
                    assert_eq!(new_state.len(), carry.len());
                    assert_eq!(new_state.len(), odds_evens.len());

                    for i in 0..new_state.len() {
                        // set m:
                        //   if is v0, v1, v2, v3: set m to m
                        //   otherwise, set m to zero
                        // TODO: check set m
                        let row = offset + (sub_round-1) * 16 * 4 + i * 4;

                        self.s_global.s_check_s_round.enable(region, row)?;
                        self.s_global.s_decompose_or_copy_in_main_round.enable(region, row)?;
                        let s = self.get_sub_round_selector(sub_round - 1, i);
                        s.enable(region, row)?; 
                        
                        // v0, v1, v2, v3
                        if i < 4 {
                            let s = PRE_COMPUTED[r % 10];
                            let m_idx = s[(sub_round-1) * 4 + i];

                            // copy m to next row
                            assigned_m[m_idx].copy_advice(|| "set m", region, columns.num, row + 1)?;
                        }

                        last_state[i] = RoundWord::assign_with_lookup(
                            || "assign new state",
                            region,
                            new_state[i],
                            row,
                            columns.num,
                            lookup,
                        )?;

                        // v0-v3, v8-v11: offset add
                        if (0..=3).contains(&i) || (8..=11).contains(&i) {
                            // assign carry to row + 2
                            region.assign_advice(|| "assign carry", columns.num, row + 2, || Value::known({
                                Fr::from(carry[i] as u64)
                            }))?;
                        } else {
                            // TODO: check! assign even carefully!

                            // xor_and_rotate
                            let even_lower_weight_part = odds_evens[i].1[0];
                            let even_heigher_weight_part = odds_evens[i].1[1];
                            let odd = odds_evens[i].0;

                            even_heigher_weight_part.map(|v| {
                                region.assign_advice(|| "assign evens[0]", columns.num, row+1, || {
                                    Value::known(Fr::from_u128(v))
                                }).unwrap();
                            });

                            even_lower_weight_part.map(|v| {
                                region.assign_advice(|| "assign evens[1]", columns.num, row+2, || {
                                    Value::known(Fr::from_u128(v))
                                }).unwrap();
                            });

                            odd.map(|v| {
                                region.assign_advice(|| "assign odds", columns.num, row+3, || {
                                    Value::known(Fr::from_u128(v))
                                }).unwrap();
                            });
                        }

                        // move this outside loop
                        last_assign_round = Some(region.assign_advice(
                            || "assign round to round",
                            self.columns.round,
                            row,
                            || Value::known(Fr::from((r+1) as u64)),
                        )?);

                        region.assign_advice(
                            || "assign s_round to 1",
                            self.columns.s_round,
                            row,
                            || Value::known(Fr::one()),
                        )?;
                    }
                }
            } else {
                for i in 0..VARS_PER_ROUND {
                    let row = offset + i * 4;
                    let j = i % vs.len();

                    self.s_global.s_check_s_round.enable(region, row)?;
                    self.s_global.s_decompose_or_copy_in_main_round.enable(region, row)?;
                    let s = self.get_sub_round_selector(i / 16, i % 16);
                    s.enable(region, row)?; 

                    // TODO: opt don't copy dense & spreads
                    last_state[j] = last_state[j].copy_into_with_lookup(region, row, &columns, lookup)?;

                    // NOTE: assign `rounds`!
                    last_assign_round = Some(region.assign_advice(
                        || "assign round to round",
                        self.columns.round,
                        row,
                        || Value::known(Fr::from(rounds as u64)),
                    )?);
                    region.assign_advice(
                        || "assign s_round to 0",
                        self.columns.s_round,
                        row,
                        || Value::known(Fr::zero()),
                    )?;

                    // TODO: check h copy?

                    // NOTE: assign next three columns to zero
                    region.assign_advice(|| "assign m | s_even0", columns.num, row + 1, || Value::known(Fr::zero()))?;
                    region.assign_advice(|| "assign carry | s_even_1", columns.num, row + 2, || Value::known(Fr::zero()))?;
                    region.assign_advice(|| "assign odd", columns.num, row + 2, || Value::known(Fr::zero()))?;
                }
            }
        }

        // make sure round is right
        region.constrain_equal(last_assign_round.unwrap().cell(), assigned_rounds.cell())?;

        Ok(last_state.into())
    }

    pub(super) fn final_h_xor(
        &self,
        region: &mut Region<'_, bn256::Fr>,
        init_state: InitializedState,
        updated_state: InnerState,
    ) -> Result<[Value<u64>; 8], Error> {
        // v0 = h0, v1 = h1...
        let h: [Value<u64>; 8] = match_state_as_array(init_state.state)
                .into_iter()
                .take(8)
                .map(|v| v.val.value_u64())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

        let vs: [Value<u64>; 16] = match_state_as_array(updated_state)
                .into_iter()
                .map(|v| v.val.value_u64())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();


        let mut offset = INIT_STATE_ROWS + (MAX_ROUND + 1) * ROWS_PER_ROUND;

        let lookup = &self.lookup;
        let columns = &self.columns;

        // TODO: check correctness
        fn spread_odd_bits_from_triple_xor(a: u64, b: u64, c: u64) -> u128 {
            let a = arb_lebs2u128(&spread_bits::<64, 128>(i2lebsp(a)));
            let b = arb_lebs2u128(&spread_bits::<64, 128>(i2lebsp(b)));
            let c = arb_lebs2u128(&spread_bits::<64, 128>(i2lebsp(c)));

            arb_lebs2u128(&spread_bits::<64, 128>(odd_bits(u1282lebsp(a + b + c))))
        }

        let mut assign_from_triple_xor = |annotation: &str, a: Value<u64>, b: Value<u64>, c: Value<u64>| {
            self.s_global.s_decompose.enable(region, offset).unwrap();
            self.s_h_xor.s_h_triple_xor.enable(region, offset).unwrap();

            let h = a.zip(b).zip(c).map(|((a, b), c)| a ^ b ^ c);
            let spread_odd: Value<u128> = a.zip(b).zip(c).map(|((a, b), c)| spread_odd_bits_from_triple_xor(a, b, c));

            let var = RoundWord::assign_with_lookup(|| annotation, region, h, offset, columns.num, &lookup)?;
            let _spread_odd = region.assign_advice(|| annotation, columns.num, offset+3, || spread_odd.map(bn256::Fr::from_u128))?;

            offset += 4;

            Result::<_, Error>::Ok(var.val.value_u64())
        };

        let mut hs = Vec::new();

        for i in 0..8 {
            hs.push(assign_from_triple_xor(&format!("assgin h{i}"), h[i], vs[i], vs[i+8])?);
        }

        Ok(hs.try_into().unwrap())
    }

    fn get_sub_round_selector(&self, sub_round: usize, i: usize) -> Selector {
        let v0 = [
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_11, 
            self.s_global.s_add_m_and_offset_neg_11,
        ];

        let v1 = [
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_11, 
            self.s_global.s_add_m_and_offset_neg_11,
        ];

        let v2 = [
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_11, 
            self.s_global.s_add_m_and_offset_neg_11,
        ];

        let v3 = [
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_12,
            self.s_global.s_add_m_and_offset_neg_15, 
            self.s_global.s_add_m_and_offset_neg_15,
        ];

        let v4 = [
            self.s_r1.s_xor_4_rotate_24,
            self.s_r2.s_xor_4_rotate_63,
            self.s_r3.s_xor_5_rotate_24,
            self.s_r4.s_xor_5_rotate_63,
        ];

        let v5 = [
            self.s_r1.s_xor_4_rotate_24,
            self.s_r2.s_xor_4_rotate_63,
            self.s_r3.s_xor_5_rotate_24,
            self.s_r4.s_xor_5_rotate_63,
        ];

        let v6 = [
            self.s_r1.s_xor_4_rotate_24,
            self.s_r2.s_xor_4_rotate_63,
            self.s_r3.s_xor_5_rotate_24,
            self.s_r4.s_xor_5_rotate_63,
        ];

        let v7 = [
            self.s_r1.s_xor_4_rotate_24,
            self.s_r2.s_xor_4_rotate_63,
            self.s_r3.s_xor_1_rotate_24,
            self.s_r4.s_xor_1_rotate_63,
        ];
        
        let v8 = [
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_5,
            self.s_global.s_add_offset_5,
        ];

        let v9 = [
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_5,
            self.s_global.s_add_offset_5,
        ];

        let v10 = [
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_5,
            self.s_global.s_add_offset_5,
        ];

        let v11 = [
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_4,
            self.s_global.s_add_offset_1,
            self.s_global.s_add_offset_1,
        ];

        let v12 = [
            self.s_r1.s_xor_neg_12_rotate_32,
            self.s_r2.s_xor_neg_12_rotate_16,
            self.s_r3.s_xor_neg_11_rotate_32,
            self.s_r4.s_xor_neg_11_rotate_16,
        ];

        let v13 = [
            self.s_r1.s_xor_neg_12_rotate_32,
            self.s_r2.s_xor_neg_12_rotate_16,
            self.s_r3.s_xor_neg_11_rotate_32,
            self.s_r4.s_xor_neg_11_rotate_16,
        ];

        let v14 = [
            self.s_r1.s_xor_neg_12_rotate_32,
            self.s_r2.s_xor_neg_12_rotate_16,
            self.s_r3.s_xor_neg_11_rotate_32,
            self.s_r4.s_xor_neg_11_rotate_16,
        ];

        let v15 = [
            self.s_r1.s_xor_neg_12_rotate_32,
            self.s_r2.s_xor_neg_12_rotate_16,
            self.s_r3.s_xor_neg_15_rotate_32,
            self.s_r4.s_xor_neg_15_rotate_16,
        ];
        
        let v = [v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15];
        
        v[i][sub_round]
    }
}


// TODO: more elegant
pub fn calc_round_state(
    vs: [Value<u64>; 16],
    m: [Value<u64>; 16],
    main_round: usize,
    sub_round: usize,
) -> ([Value<u64>; 16], [u32; 16], [(Value<u128>, [Value<u128>; 2]); 16]) {
    assert_ne!(sub_round, 0);
    assert!(sub_round <= 4);

    let mut v0 = vs[0];
    let mut v1 = vs[1];
    let mut v2 = vs[2];
    let mut v3 = vs[3];
    let mut v4 = vs[4];
    let mut v5 = vs[5];
    let mut v6 = vs[6];
    let mut v7 = vs[7];
    let mut v8 = vs[8];
    let mut v9 = vs[9];
    let mut v10 = vs[10];
    let mut v11 = vs[11];
    let mut v12 = vs[12];
    let mut v13 = vs[13];
    let mut v14 = vs[14];
    let mut v15 = vs[15];

    let mut c = [0_u32; 16];

    let mut odds_evens: [(Value<u128>, [Value<u128>; 2]); 16] =
        [(Value::unknown(), [Value::unknown(); 2]); 16];

    fn reset_carry(carry: &mut [u32]) {
        for v in carry {
            *v = 0;
        }
    }

    macro_rules! sadd {
        ($a:expr, $b:expr) => {{
            let mut carry = 0;
            $a = $a.zip($b).map(|(l, r)| {
                let (v, c) = l.overflowing_add(r);
                carry = c as u32;
                v
            });
            carry
        }};

        ($a:expr, $b:expr, $c:expr) => {{
            let mut carry = 0;
            $a = $a.zip($b).zip($c).map(|((l, r0), r1)| {
                let (v, c0) = l.overflowing_add(r0);
                let (v, c1) = v.overflowing_add(r1);
                carry = c0 as u32 + c1 as u32;
                v
            });
            carry
        }};
    }

    macro_rules! xor_and_rotate {
        ($a:expr, $b:expr, $rotate:expr) => {{
            let odd = $a.zip($b).map(|(l, r)| get_spread_old(l, r));
            let e0 = $a.zip($b).map(|(l, r)| get_spread_even(l, r, $rotate)[0]);
            let e1 = $a.zip($b).map(|(l, r)| get_spread_even(l, r, $rotate)[1]);
            $a = $a.zip($b).map(|(l, r)| (l ^ r).rotate_right($rotate));

            (odd, [e0, e1])
        }};
    }

    for i in 0..(main_round+1) {
        let is_last_round = i == main_round;

        let s = PRE_COMPUTED[i % 10];

        let sub_r = 1;
        reset_carry(&mut c[..]);

        // sub round 1
        c[0] = sadd!(v0, m[s[0]], v4);
        odds_evens[12] = xor_and_rotate!(v12, v0, 32);
        c[8] = sadd!(v8, v12);
        odds_evens[4] = xor_and_rotate!(v4, v8, 24);
        c[1] = sadd!(v1, m[s[1]], v5);
        odds_evens[13] = xor_and_rotate!(v13, v1, 32);
        c[9] = sadd!(v9, v13);
        odds_evens[5] = xor_and_rotate!(v5, v9, 24);
        c[2] = sadd!(v2, m[s[2]], v6);
        odds_evens[14] = xor_and_rotate!(v14, v2, 32);
        c[10] = sadd!(v10, v14);
        odds_evens[6] = xor_and_rotate!(v6, v10, 24);
        c[3] = sadd!(v3, m[s[3]], v7);
        odds_evens[15] = xor_and_rotate!(v15, v3, 32);
        c[11] = sadd!(v11, v15);
        odds_evens[7] = xor_and_rotate!(v7, v11, 24);

        if is_last_round && sub_r == sub_round {
            break;
        }

        let sub_r = 2;
        reset_carry(&mut c[..]);

        // sub round 2
        c[0] = sadd!(v0, m[s[4]], v4);
        odds_evens[12] = xor_and_rotate!(v12, v0, 16);
        c[8] = sadd!(v8, v12);
        odds_evens[4] = xor_and_rotate!(v4, v8, 63);
        c[1] = sadd!(v1, m[s[5]], v5);
        odds_evens[13] = xor_and_rotate!(v13, v1, 16);
        c[9] = sadd!(v9, v13);
        odds_evens[5] = xor_and_rotate!(v5, v9, 63);
        c[2] = sadd!(v2, m[s[6]], v6);
        odds_evens[14] = xor_and_rotate!(v14, v2, 16);
        c[10] = sadd!(v10, v14);
        odds_evens[6] = xor_and_rotate!(v6, v10, 63);
        c[3] = sadd!(v3, m[s[7]], v7);
        odds_evens[15] = xor_and_rotate!(v15, v3, 16);
        c[11] = sadd!(v11, v15);
        odds_evens[7] = xor_and_rotate!(v7, v11, 63);

        if is_last_round && sub_r == sub_round {
            break;
        }

        reset_carry(&mut c[..]);

        let sub_r = 3;
        reset_carry(&mut c[..]);

        // sub round 3
        c[0] = sadd!(v0, m[s[8]], v5);
        odds_evens[15] = xor_and_rotate!(v15, v0, 32);
        c[10] = sadd!(v10, v15);
        odds_evens[5] = xor_and_rotate!(v5, v10, 24);
        c[1] = sadd!(v1, m[s[9]], v6);
        odds_evens[12] = xor_and_rotate!(v12, v1, 32);
        c[11] = sadd!(v11, v12);
        odds_evens[6] = xor_and_rotate!(v6, v11, 24);
        c[2] = sadd!(v2, m[s[10]], v7);
        odds_evens[13] = xor_and_rotate!(v13, v2, 32);
        c[8] = sadd!(v8, v13);
        odds_evens[7] = xor_and_rotate!(v7, v8, 24);
        c[3] = sadd!(v3, m[s[11]], v4);
        odds_evens[14] = xor_and_rotate!(v14, v3, 32);
        c[9] = sadd!(v9, v14);
        odds_evens[4] = xor_and_rotate!(v4, v9, 24);

        if is_last_round && sub_r == sub_round {
            break;
        }

        reset_carry(&mut c[..]);

        // sub round 4
        c[0] = sadd!(v0, m[s[12]], v5);
        odds_evens[15] = xor_and_rotate!(v15, v0, 16);
        c[10] = sadd!(v10, v15);
        odds_evens[5] = xor_and_rotate!(v5, v10, 63);
        c[1] = sadd!(v1, m[s[13]], v6);
        odds_evens[12] = xor_and_rotate!(v12, v1, 16);
        c[11] = sadd!(v11, v12);
        odds_evens[6] = xor_and_rotate!(v6, v11, 63);
        c[2] = sadd!(v2, m[s[14]], v7);
        odds_evens[13] = xor_and_rotate!(v13, v2, 16);
        c[8] = sadd!(v8, v13);
        odds_evens[7] = xor_and_rotate!(v7, v8, 63);
        c[3] = sadd!(v3, m[s[15]], v4);
        odds_evens[14] = xor_and_rotate!(v14, v3, 16);
        c[9] = sadd!(v9, v14);
        odds_evens[4] = xor_and_rotate!(v4, v9, 63);
    }

    (
        [
            v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15,
        ],
        c,
        odds_evens,
    )
}

use crate::util::{arb_lebs2u128, spread_even_bits_from_xor, spread_odd_u128_from_xor};

fn get_spread_old(v: u64, xor: u64) -> u128 {
    spread_odd_u128_from_xor(v, xor)
}

fn get_spread_even(v: u64, xor: u64, rotate: u32) -> [u128; 2] {
    let even = spread_even_bits_from_xor(v, xor);
    let rotate = rotate as usize * 2;

    let lo = &even[..rotate];
    let hi = &even[rotate..];

    [arb_lebs2u128(lo), arb_lebs2u128(hi)]
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, Error, ConstraintSystem},
    };

    use super::*;
    use crate::{compression::CompressionConfig, spread_table::{SpreadTableChip, SpreadTableConfig}, scheduler::SchedulerConfig, chip::Columns};

    #[test]
    fn test_blake_round_core()  {
        let vs: [Value<u64>; 16] = [Value::known(5577006791947779410),Value::known(15352856648520921629),Value::known(0),Value::known(9828766684487745566),Value::known(894385949183117216),Value::known(4751997750760398084),Value::known(11199607447739267382),Value::known(12156940908066221323),Value::known(11833901312327420776),Value::known(6263450610539110790),Value::known(1874068156324778273),Value::known(14486903973548550719),Value::known(11926873763676642186),Value::known(6941261091797652072),Value::known(17204678798284737396),Value::known(4831389563158288344)];
        let m: [Value<u64>; 16] = [Value::known(8674665223082153551),Value::known(13260572831089785859),Value::known(6334824724549167320),Value::known(10667007354186551956),Value::known(11998794077335055257),Value::known(7504504064263669287),Value::known(3510942875414458836),Value::known(4324745483838182873),Value::known(11926759511765359899),Value::known(11239168150708129139),Value::known(3328451335138149956),Value::known(7955079406183515637),Value::known(2740103009342231109),Value::known(1905388747193831650),Value::known(15649472107743074779),Value::known(261049867304784443)];
        let expected_new_vs: [Value<u64>; 16] = [Value::known(1167885585688411048),Value::known(9132935703036027322),Value::known(13125040812557909567),Value::known(6112539474157580159),Value::known(3133968705664923835),Value::known(11042207055073639687),Value::known(10955020035800245616),Value::known(2831786654526290545),Value::known(1006267388626854281),Value::known(939610873840029904),Value::known(1829487957615954457),Value::known(18058344788569079972),Value::known(6582351318386615796),Value::known(4798940882642563951),Value::known(15738503566863505976),Value::known(14605998900807323338)];

        let round = 11;
        let sub_round = 4;
        let (new_vs, _, _) = calc_round_state(vs, m, round, sub_round);
        for i in 0..16 {
            let v = expected_new_vs[i].zip(new_vs[i]).map(|(l, r)| { assert_eq!(l, r); l + r });
            println!("{:?}", v);
        }
    }
}
