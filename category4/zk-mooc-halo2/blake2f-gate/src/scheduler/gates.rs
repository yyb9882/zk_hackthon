use halo2_proofs::{
    plonk::{ConstraintSystem, Constraints, Expression}, poly::Rotation,
};
use halo2curves::bn256::{self, Fr};

use super::SchedulerConfig;
use crate::{spread_table::SpreadInputs, chip::{query_table, compose_dense_from_bits, compose_spread_from_bits, Columns}};


impl SchedulerConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<bn256::Fr>,
        lookup: SpreadInputs,
        columns: Columns,
    ) -> Self {
        // TODO: use global decompose selector
        let s_xor_v12_v13_v14 = meta.selector();
        let s_decompose = meta.selector();

        // TODO: global selector
        meta.create_gate("decompose a u64 to 4 * u16", |meta| {
            let s = meta.query_selector(s_decompose);

            let val = meta.query_advice(columns.num, Rotation::cur());
            let (dense, _) = query_table(meta, &lookup, Rotation::cur());

            vec![s * (val - compose_dense_from_bits(&dense))]
        });

        meta.create_gate("xor v12 v13 v14", |meta| {
            // old v12: Rotation(-24)
            // c0: Rotation(-12)

            let s = meta.query_selector(s_xor_v12_v13_v14);

            let (_, s_old_v) = query_table(meta, &lookup, Rotation(-24));
            let (_, s_rhs) = query_table(meta, &lookup, Rotation(-12));

            let (_, v) = query_table(meta, &lookup, Rotation::cur());
            let v_spread_odd = meta.query_advice(columns.num, Rotation(3));

            // v(spread_even) + v_spread_odd = s_old_v + s_rhs

            let old_v = compose_spread_from_bits(&s_old_v);
            let rhs = compose_spread_from_bits(&s_rhs);

            let v = compose_spread_from_bits(&v);

            Constraints::with_selector(
                s,
                vec![v + v_spread_odd * Expression::Constant(Fr::from(2))  - old_v - rhs],
            )
        });

        SchedulerConfig {
            lookup,
            columns,
            s_decompose,
            s_xor_v12_v13_v14,
        }
    }
}
