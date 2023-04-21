use halo2_proofs::{
    plonk::{ConstraintSystem, Constraints, Expression, Selector},
    poly::Rotation,
};
use halo2curves::FieldExt;
use halo2curves::{bn256::{self, Fr}};

use crate::{compression::SpreadInputs, MAX_ROUND};
use crate::compression::compose_dense_from_bits;
use crate::compression::ROWS_PER_ROUND;
use crate::chip::{Columns, query_table, compose_spread_from_bits};


// TODD: move to global
#[derive(Debug, Clone)]
pub struct RoundGates {
    pub s_add_offset_1: Selector,
    pub s_add_offset_4: Selector,
    pub s_add_offset_5: Selector,

    pub s_add_m_and_offset_neg_15: Selector,
    pub s_add_m_and_offset_neg_12: Selector,
    pub s_add_m_and_offset_neg_11: Selector,

    pub s_decompose: Selector, // normal decompose

    // check decompose when Fp(s_round) == 1 otherwise check state copy
    pub s_decompose_or_copy_in_main_round: Selector,


    // enable s_round in main round
    pub s_check_s_round: Selector,
}

impl RoundGates {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<bn256::Fr>,
        // message_schedule: Column<Advice>,
        columns: &Columns,
        lookup: &SpreadInputs,
    ) -> Self {
        let s_add_offset_1 = meta.selector();
        let s_add_offset_4 = meta.selector();
        let s_add_offset_5 = meta.selector();

        let s_add_m_and_offset_neg_15 = meta.selector();
        let s_add_m_and_offset_neg_12 = meta.selector();
        let s_add_m_and_offset_neg_11 = meta.selector();

        let s_decompose_or_copy_in_main_round = meta.selector();
        let s_decompose = meta.selector();
        let s_main_round = meta.selector();
        let s_digest = meta.selector();

        let s_check_s_round = meta.selector();

        meta.create_gate("decompose or copy in main round", |meta| {
            let s = meta.query_selector(s_decompose_or_copy_in_main_round);
            let s_round = meta.query_advice(columns.s_round, Rotation::cur());

            let old_val = meta.query_advice(columns.num, Rotation(-16 * 4));
            let val = meta.query_advice(columns.num, Rotation::cur());

            let (val_dense_bits, _) = query_table(meta, &lookup, Rotation::cur());

            let dense_val = compose_dense_from_bits(&val_dense_bits);

            let decompose_check = s_round.clone() * (val.clone() - dense_val);
            let copy_check = (Expression::Constant(Fr::one()) - s_round) * (old_val - val);

            Constraints::with_selector(s, vec![
                decompose_check,
                copy_check,
            ])
        });

        meta.create_gate("decompose check", |meta| {
            let s = meta.query_selector(s_decompose);

            let val = meta.query_advice(columns.num, Rotation::cur());

            let (dense_bits, _) = query_table(meta, &lookup, Rotation::cur());
            let dense_val = compose_dense_from_bits(&dense_bits);

            Constraints::with_selector(s, vec![
                val - dense_val,
            ])
        });

        meta.create_gate("check round as a selector", |meta| {
            let s_check_s_round = meta.query_selector(s_check_s_round);

            let s_round = meta.query_advice(columns.s_round, Rotation::cur());
            let round = meta.query_advice(columns.round, Rotation::cur());

            // TODO: make next constant
            let s_round_prev = meta.query_advice(columns.s_round, Rotation(-(ROWS_PER_ROUND as i32)));
            let round_prev = meta.query_advice(columns.round, Rotation(-(ROWS_PER_ROUND as i32)));

            let one = Expression::Constant(Fr::one());

            Constraints::with_selector(s_check_s_round, vec![
                (s_round.clone() * (one.clone() - s_round.clone())), // s_round must be a boolean
                (s_round.clone() * (one.clone() - s_round_prev.clone())), // if s_round is one, then the prev s_round must be one
                // if s_round: cur_round - prev_cound = 1
                (s_round.clone() * (round.clone() - round_prev.clone() - one.clone())),
                // if not s_round: cur_round == prev_round
                (one.clone() - s_round.clone()) * (round_prev.clone() - round.clone()),
            ])
        });

        offset_add_gate::<1, false>("offset_add_1", meta, s_add_offset_1, &columns);
        offset_add_gate::<4, false>("offset_add_4", meta, s_add_offset_4, &columns);
        offset_add_gate::<5, false>("offset_add_5", meta, s_add_offset_5, &columns);

        offset_add_gate::<-15, true>("offset_add_1_and_m", meta, s_add_m_and_offset_neg_15, &columns);
        offset_add_gate::<-12, true>("offset_add_4_and_m", meta, s_add_m_and_offset_neg_12, &columns);
        offset_add_gate::<-11, true>("offset_add_5_and_m", meta, s_add_m_and_offset_neg_11, &columns);

        RoundGates {
            s_add_offset_1,
            s_add_offset_4,
            s_add_offset_5,
            s_add_m_and_offset_neg_15,
            s_add_m_and_offset_neg_12,
            s_add_m_and_offset_neg_11,
            s_decompose,
            s_decompose_or_copy_in_main_round,

            s_check_s_round,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubRound1Gates {
    pub s_xor_neg_12_rotate_32: Selector,
    pub s_xor_4_rotate_24: Selector,
}

impl SubRound1Gates {
    pub fn configure(meta: &mut ConstraintSystem<bn256::Fr>, columns: &Columns, lookup: &SpreadInputs) -> Self {
        let s_xor_neg_12_rotate_32 = meta.selector();
        let s_xor_4_rotate_24 = meta.selector();

        xor_and_rotate_gate::<-12, 32>("xor(-12) and rotate 32", meta, s_xor_neg_12_rotate_32, columns, lookup);
        xor_and_rotate_gate::<4, 24>("xor(+4) and rotate 24", meta, s_xor_4_rotate_24, columns, lookup);

        Self {
            s_xor_neg_12_rotate_32,
            s_xor_4_rotate_24,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubRound2Gates {
    pub s_xor_neg_12_rotate_16: Selector,
    pub s_xor_4_rotate_63: Selector,
}

impl SubRound2Gates {
    pub fn configure(meta: &mut ConstraintSystem<bn256::Fr>, columns: &Columns, lookup: &SpreadInputs) -> Self {
        let s_xor_neg_12_rotate_16 = meta.selector();
        let s_xor_4_rotate_63 = meta.selector();

        xor_and_rotate_gate::<-12, 16>("xor(-12) and rotate 16", meta, s_xor_neg_12_rotate_16, columns, lookup);
        xor_and_rotate_gate::<4, 63>("xor(+4) and rotate 63", meta, s_xor_4_rotate_63, columns, lookup);

        Self {
            s_xor_neg_12_rotate_16,
            s_xor_4_rotate_63,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubRound3Gates {
    pub s_xor_neg_15_rotate_32: Selector,
    pub s_xor_neg_11_rotate_32: Selector,
    pub s_xor_5_rotate_24: Selector,
    pub s_xor_1_rotate_24: Selector,
}

impl SubRound3Gates {
    pub fn configure(meta: &mut ConstraintSystem<bn256::Fr>, columns: &Columns, lookup: &SpreadInputs) -> Self {
        let s_xor_neg_15_rotate_32 = meta.selector();
        let s_xor_neg_11_rotate_32 = meta.selector();
        let s_xor_5_rotate_24 = meta.selector();
        let s_xor_1_rotate_24 = meta.selector();

        xor_and_rotate_gate::<-11, 32>("xor(-11) and rotate 32", meta, s_xor_neg_11_rotate_32, columns, lookup);
        xor_and_rotate_gate::<-15, 32>("xor(-15) and rotate 32", meta, s_xor_neg_15_rotate_32, columns, lookup);
        xor_and_rotate_gate::<1, 24>("xor(+1) and rotate 24", meta, s_xor_1_rotate_24, columns, lookup);
        xor_and_rotate_gate::<5, 24>("xor(+5) and rotate 24", meta, s_xor_5_rotate_24, columns, lookup);

        Self {
            s_xor_1_rotate_24,
            s_xor_5_rotate_24,
            s_xor_neg_11_rotate_32,
            s_xor_neg_15_rotate_32,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubRound4Gates {
    pub s_xor_neg_15_rotate_16: Selector,
    pub s_xor_neg_11_rotate_16: Selector,
    pub s_xor_5_rotate_63: Selector,
    pub s_xor_1_rotate_63: Selector,
}

impl SubRound4Gates {
    pub fn configure(meta: &mut ConstraintSystem<bn256::Fr>, columns: &Columns, lookup: &SpreadInputs) -> Self {
        let s_xor_neg_15_rotate_16 = meta.selector();
        let s_xor_neg_11_rotate_16 = meta.selector();
        let s_xor_5_rotate_63 = meta.selector();
        let s_xor_1_rotate_63 = meta.selector();

        xor_and_rotate_gate::<-11, 16>("xor(-11) and rotate 16", meta, s_xor_neg_11_rotate_16, columns, lookup);
        xor_and_rotate_gate::<-15, 16>("xor(-15) and rotate 16", meta, s_xor_neg_15_rotate_16, columns, lookup);
        xor_and_rotate_gate::<1, 63>("xor(+1) and rotate 63", meta, s_xor_1_rotate_63, columns, lookup);
        xor_and_rotate_gate::<5, 63>("xor(+5) and rotate 63", meta, s_xor_5_rotate_63, columns, lookup);

        Self {
            s_xor_1_rotate_63,
            s_xor_5_rotate_63,
            s_xor_neg_11_rotate_16,
            s_xor_neg_15_rotate_16,
        }
    }
}


#[derive(Debug, Clone)]
pub struct HxorGates {
    pub s_h_triple_xor: Selector,
}

impl HxorGates {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<bn256::Fr>,
        columns: &Columns,
        lookup: &SpreadInputs,
    ) -> Self {
        let s_h_triple_xor = meta.selector();
        meta.create_gate("h_xor", |meta| {
            let s = meta.query_selector(s_h_triple_xor);

            let (_, h_prev_spread) = query_table(meta, lookup, Rotation(-1 * (MAX_ROUND as i32+1) * ROWS_PER_ROUND as i32));
            let (_, v_l_spread) = query_table(meta, lookup, Rotation(-16 * 4));
            let (_, v_r_spread) = query_table(meta, lookup, Rotation(-8 * 4));

            // h_spread is the even bits
            let (_, h_spread) = query_table(meta, lookup, Rotation::cur());
            // let new_spread_bits = query_columns::<4>(meta, &columns.spread_bits, Rotation::cur());
            let h_odd_spread = meta.query_advice(columns.num, Rotation(3));

            let h_prev_spread = compose_spread_from_bits(&h_prev_spread);
            let v_l_spread = compose_spread_from_bits(&v_l_spread);
            let v_r_spread = compose_spread_from_bits(&v_r_spread);
            let h_spread = compose_spread_from_bits(&h_spread);

            Constraints::with_selector(
                s,
                vec![
                    h_prev_spread + v_l_spread + v_r_spread -
                        (h_spread + h_odd_spread * Expression::Constant(Fr::from(2))),
                ],
            )
        });

        Self {
            s_h_triple_xor,
        }
    }
}


fn offset_add_gate<const OFFSET: i32, const ADD_M: bool>(
    name: &'static str,
    meta: &mut ConstraintSystem<bn256::Fr>,
    selector: Selector,
    columns: &Columns,
) {
    if ADD_M {
        assert!(OFFSET < 0);
    }

    meta.create_gate(name, |meta| {
        let s = meta.query_selector(selector);

        let prev_val = meta.query_advice(columns.num, Rotation(-16 * 4));
        let rhs = meta.query_advice(columns.num, Rotation(OFFSET * 4));

        let new_val = meta.query_advice(columns.num, Rotation::cur());

        // let m = if ADD_M {
        //     meta.query_advice(columns.num, Rotation)
        // }
        let m = if ADD_M {
            meta.query_advice(columns.num, Rotation::next())
        } else {
            Expression::Constant(bn256::Fr::zero())
        };

        let carry = meta.query_advice(columns.num, Rotation(2));

        let s_round = meta.query_advice(columns.s_round, Rotation::cur());

        // TODO: check carry in [0, 1] ?

        // cur + 2^64 * carry = old_val + rhs + m(optional)

        let mut check = s_round.clone() *
            (
                new_val + carry * Expression::Constant(Fr::from_u128(1 << 64))
                    - prev_val - rhs - m
            );

        Constraints::with_selector(s, vec![check])
    });
}

pub(crate) fn xor_and_rotate_gate<const XOR: i32, const R: usize>(
    name: &'static str,
    meta: &mut ConstraintSystem<bn256::Fr>,
    selector: Selector,
    columns: &Columns,
    lookup: &SpreadInputs,
) {
    meta.create_gate(name, |meta| {
        let s = meta.query_selector(selector);

        let v_s_even_0 = meta.query_advice(columns.num, Rotation::next());
        let v_s_even_1 = meta.query_advice(columns.num, Rotation(2));
        let v_s_odd = meta.query_advice(columns.num, Rotation(3));

        let (_, cur_spread_bits) = query_table(meta, lookup, Rotation::cur());

        let (_, old_spread_bits) = query_table(meta, lookup, Rotation(-16 * 4));
        let (_, rhs_spread_bits) = query_table(meta, lookup, Rotation(XOR * 4));

        let v_s_old = compose_spread_from_bits(&old_spread_bits);
        let v_s_cur = compose_spread_from_bits(&cur_spread_bits);
        let v_s_rhs = compose_spread_from_bits(&rhs_spread_bits);

        // TODO: change assign
        let even_before_rotate = v_s_even_0.clone() * Expression::Constant(bn256::Fr::from_u128(1 << (R * 2))) + v_s_even_1.clone();
        let even_after_rotate = v_s_even_1 * Expression::Constant(bn256::Fr::from_u128(1 << (128 - R * 2))) + v_s_even_0;

        let s_round = meta.query_advice(columns.s_round, Rotation::cur());

        let check_xor = (even_before_rotate + v_s_odd * Expression::Constant(bn256::Fr::from(2)))
            - v_s_old - v_s_rhs;

        let check_spread_equality = even_after_rotate - v_s_cur;

        Constraints::with_selector(
            s,
            vec![
                s_round.clone() * check_xor,
                s_round.clone() * check_spread_equality,
            ],
        )
    });
}
