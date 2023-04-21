use std::borrow::BorrowMut;

use halo2_proofs::{
    plonk::Error,
    circuit::{Value, Layouter},
};
use halo2curves::{FieldExt, bn256::{self, Fr}};

use super::SchedulerConfig;
use crate::{state::{InnerState, RoundWord}, util::spread_odd_u128_from_xor};
use crate::InitializedState;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

impl SchedulerConfig {
    pub fn process(
        &self,
        layouter: &mut impl Layouter<bn256::Fr>,
        h: [Value<u64>; 8],
        m: [Value<u64>; 16],
        c0: Value<u64>,
        c1: Value<u64>,
        flag: Value<u64>,
        rounds: Value<u64>,
    )  -> Result<InitializedState, Error> {
        let lookup = self.lookup.clone();

        // v0, v1, v2, v3, v4, v5, v6, v7 := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
        // v8, v9, v10, v11, v12, v13, v14, v15 := iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]
        // v12 ^= c0
        // v13 ^= c1
        // v14 ^= flag
        layouter.assign_region(|| "scheduler process", |mut region| {
            let num_column = self.columns.num;
            let fixed_column = self.columns.constants;
            let mut ivs = Vec::new();
            let mut assigned_m = Vec::new();

            // Assign IV to fixed column
            for i in 0..IV.len() {
                ivs.push(
                    region.assign_fixed(
                        || {format!("assign iv {i}")} ,
                        fixed_column,
                        i,
                        || Value::known(Fr::from(IV[i]))
                    )?
                );
            }

            // Assign round
            let assigned_rounds = region.assign_advice(
                || "assign rounds",
                self.columns.round,
                0,
                || rounds.map(Fr::from)
            )?;


            // Assign `m` into the ROUND COLUMN
            for (i, v) in m.into_iter().enumerate() {
                assigned_m.push(region.assign_advice(
                    || format!("assign m{i}"),
                    self.columns.round,
                    i+1, // 0 already assigned to `round`
                    || v.map(Fr::from),
                )?);
            }

            // Assign v0-v11, v15 without lookup
            // let mut offset = 0;

            use std::rc::Rc;
            use std::cell::RefCell;
            
            // let mut offset = Rc::new();
            let region: Rc<RefCell<_>> = Rc::new(RefCell::new(region));
            let offset = Rc::new(RefCell::new(0usize));

            // we borrow mutable ref in two closure
            let assign_round = |annotation: &'static str, val: Value<u64>, with_lookup: bool| {
                let region_cell = region.clone();
                let mut region = region_cell.try_borrow_mut().unwrap();

                let offset_cell = offset.clone();
                let mut offset = offset_cell.try_borrow_mut().unwrap();

                let var = if with_lookup {
                    self.s_decompose.enable(&mut region, *offset).unwrap();
                    RoundWord::assign_with_lookup(|| annotation, &mut region, val, *offset, num_column, &lookup)
                } else {
                    RoundWord::assign_without_lookup(|| annotation, &mut region, val, *offset, num_column)
                };

                if with_lookup {
                    *offset += 4;
                } else {
                    *offset += 1;
                }

                var
            };

            let assign_updated_v12_v13_v14 = |annotation: &'static str, val: Value<u64>, spread_odd: Value<u128>| {
                let region_cell = region.clone();
                let mut region = region_cell.try_borrow_mut().unwrap();

                let offset_cell = offset.clone();
                let mut offset = offset_cell.try_borrow_mut().unwrap();

                self.s_decompose.enable(&mut region, *offset).unwrap();
                let var = RoundWord::assign_with_lookup(|| annotation, &mut region, val, *offset, num_column, &lookup);

                self.s_xor_v12_v13_v14.enable(&mut region, *offset).unwrap();

                region.assign_advice(
                    || "assign spread_odd",
                    num_column,
                    *offset + 3,
                    || spread_odd.map(Fr::from_u128),
                )?;

                *offset += 4;

                var
            };

            // assign v0-v7 without lookup
            let v0 = assign_round("assign v0", h[0], false)?;
            let v1 = assign_round("assign v1", h[1], false)?;
            let v2 = assign_round("assign v2", h[2], false)?;
            let v3 = assign_round("assign v3", h[3], false)?;
            let v4 = assign_round("assign v4", h[4], false)?;
            let v5 = assign_round("assign v5", h[5], false)?;
            let v6 = assign_round("assign v6", h[6], false)?;
            let v7 = assign_round("assign v7", h[7], false)?;

            // assign v8-v11 without lookup
            let v8 = assign_round("assign v8", Value::known(IV[0]), false)?;
            let v9 = assign_round("assign v9", Value::known(IV[1]), false)?;
            let v10 = assign_round("assign v10", Value::known(IV[2]), false)?;
            let v11 = assign_round("assign v11", Value::known(IV[3]), false)?;

            // assign v15 without lookup
            let v15 = assign_round("assign v15", Value::known(IV[7]), false)?;

            // assign old v12, v13, v14 with lookup
            let old_v12 = assign_round("assign old v12", Value::known(IV[4]), true)?;
            let old_v13 = assign_round("assign old v13", Value::known(IV[5]), true)?;
            let old_v14 = assign_round("assign old v14", Value::known(IV[6]), true)?;


            // assign c0, c1, flag with lookup
            let _var_c0 = assign_round("assign c0", c0, true)?;
            let _var_c1 = assign_round("assign c1", c1, true)?;
            let _var_flag = assign_round("assign flag", flag, true)?;


            // assign updated v12,v13,v14
            let v12 = assign_updated_v12_v13_v14(
                "assign v12 = IV[4]^c0",
                c0.map(|c0| IV[4] ^ c0),
                c0.map(|c0| spread_odd_u128_from_xor(IV[4], c0)),
            )?;
            let v13 = assign_updated_v12_v13_v14(
                "assign v13 = IV[5]^c1",
                c1.map(|c| IV[5] ^ c),
                c1.map(|c| spread_odd_u128_from_xor(IV[5], c)),
            )?;
            let v14 = assign_updated_v12_v13_v14(
                "assign v14 = IV[6]^flag",
                flag.map(|flag| IV[6] ^ flag),
                flag.map(|f| spread_odd_u128_from_xor(IV[6], f)),
            )?;

            // enforce copy from IVs
            let mut region = region.try_borrow_mut().unwrap();
            region.constrain_equal(old_v12.val.cell(), ivs[4].cell())?;
            region.constrain_equal(old_v13.val.cell(), ivs[5].cell())?;
            region.constrain_equal(old_v14.val.cell(), ivs[6].cell())?;

            region.constrain_equal(v8.val.cell(), ivs[0].cell())?;
            region.constrain_equal(v9.val.cell(), ivs[1].cell())?;
            region.constrain_equal(v10.val.cell(), ivs[2].cell())?;
            region.constrain_equal(v11.val.cell(), ivs[3].cell())?;
            region.constrain_equal(v15.val.cell(), ivs[7].cell())?;

            let state = InitializedState {
                state: InnerState::new(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15),
                round: assigned_rounds,
                m: assigned_m.try_into().unwrap(),
            };

            Ok(state)
        })
    }

}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, Error, Instance, Column, ConstraintSystem},
    };

    use crate::{spread_table::{SpreadTableChip, SpreadTableConfig}, bits::AssignedBits, chip::Columns};

    use super::*;

    #[test]
    fn test_assign() {
        #[derive(Default)]
        pub struct MyCircuit {
            pub inputs: Blake2fWitness,
            outputs: [u64; 16]
        }

        #[derive(Clone, Debug)]
        pub struct CircuitConfig {
            lookup_config: SpreadTableConfig,
            scheduler_config: SchedulerConfig,
        }

        #[derive(Clone, Debug, Default)]
        pub struct Blake2fWitness {
            pub rounds: u32,
            pub h: [u64; 8],
            pub m: [u64; 16],
            pub t: [u64; 2],
            pub f: bool,
        }

        impl Circuit<bn256::Fr> for MyCircuit {
            type Config = CircuitConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<bn256::Fr>) -> Self::Config {
                let columns = Columns::init(meta);
                let input_dense = meta.advice_column();
                let input_spread = meta.advice_column();
                let lookup = SpreadTableChip::configure(meta, input_dense, input_spread);
                let extra_config = SchedulerConfig::configure(meta, lookup.input.clone(), columns);
                for column in [input_dense, input_spread].iter() {
                    meta.enable_equality(*column);
                }

                CircuitConfig {
                    lookup_config: lookup,
                    scheduler_config: extra_config
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<bn256::Fr>,
            ) -> Result<(), Error> {
                SpreadTableChip::load(config.lookup_config, &mut layouter)?;
                let init_state = config.scheduler_config.process(
                    &mut layouter,
                    self.inputs.h.iter().map(|v| Value::known(*v)).collect::<Vec<_>>().try_into().unwrap(),
                    self.inputs.m.iter().map(|v| Value::known(*v)).collect::<Vec<_>>().try_into().unwrap(),
                    Value::known(self.inputs.t[0]),
                    Value::known(self.inputs.t[1]),
                    Value::known(self.inputs.f as u64),
                    Value::known(self.inputs.rounds as u64),
                )?;

                let state = init_state.state;
                state.v0.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[0]));
                state.v1.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[1]));
                state.v2.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[2]));
                state.v3.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[3]));
                state.v4.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[4]));
                state.v5.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[5]));
                state.v6.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[6]));
                state.v7.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[7]));
                state.v8.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[8]));
                state.v9.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[9]));
                state.v10.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[10]));
                state.v11.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[11]));
                state.v12.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[12]));
                state.v13.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[13]));
                state.v14.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[14]));
                state.v15.unwrap().val.value_u64().map(|v| assert_eq!(v, self.outputs[15]));

                Ok(())
            }
        }

        let h = (0..8).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
        let t = (0..2).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
        let f = fastrand::bool();

        let mut outputs = h.to_vec();
        outputs.extend_from_slice(&IV[0..8]);

        outputs[12] = outputs[12] ^ t[0];
        outputs[13] = outputs[13] ^ t[1];
        outputs[14] = outputs[14] ^ (f as u64);

        let circuit: MyCircuit = MyCircuit {
            inputs: Blake2fWitness {
                rounds: 12,
                h: h.clone().try_into().unwrap(),
                m: [0; 16],
                t : t.clone().try_into().unwrap(),
                f,
            },
            outputs: outputs.try_into().unwrap(),
        };

        let prover = match MockProver::<bn256::Fr>::run(17, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}