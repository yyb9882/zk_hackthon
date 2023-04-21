use halo2_proofs::{
    plonk::{ConstraintSystem, Constraints, Expression, Selector, Error},
    poly::Rotation,
    circuit::{Layouter, Value},
};
use halo2curves::{FieldExt, bn256::{self, Fr}};

use crate::{spread_table::SpreadInputs, chip::compose_dense_from_bits};
use crate::chip::Columns;

mod assignment;
mod gates;
mod test;

use gates::*;

use self::assignment::ROWS_PER_ROUND;

#[derive(Clone, Debug)]
pub struct CompressionConfig {
    columns: Columns,
    lookup: SpreadInputs,
    s_global: RoundGates,
    s_r1: SubRound1Gates,
    s_r2: SubRound2Gates,
    s_r3: SubRound3Gates,
    s_r4: SubRound4Gates,

    s_h_xor: HxorGates,
}

impl CompressionConfig {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<bn256::Fr>,
        lookup: SpreadInputs,
        // message_schedule: Column<Advice>,
        columns: Columns,
    ) -> Self {
        let s_global = RoundGates::configure(meta, &columns, &lookup);
        let s_r1 = SubRound1Gates::configure(meta, &columns, &lookup);
        let s_r2 = SubRound2Gates::configure(meta, &columns, &lookup);
        let s_r3 = SubRound3Gates::configure(meta, &columns, &lookup);
        let s_r4 = SubRound4Gates::configure(meta, &columns, &lookup);

        let s_h_xor = HxorGates::configure(meta, &columns, &lookup);

        Self {
            columns,
            lookup,
            s_global,
            s_r1,
            s_r2,
            s_r3,
            s_r4,
            s_h_xor,
        }
    }

    pub fn compress(
        &self,
        layouter: &mut impl Layouter<bn256::Fr>,
        init_state: crate::InitializedState,
        rounds: Value<u64>,
        m: [Value<u64>; 16], //TODO: assigned bits?
    ) -> Result<[Value<u64>; 8], Error>{
        layouter.assign_region(|| "compress", |mut region| {
            let updated_state = self.assign_round(&mut region, init_state.clone(), rounds, m)?;
            self.final_h_xor(&mut region, init_state.clone(), updated_state.clone())
        })
    }
}
