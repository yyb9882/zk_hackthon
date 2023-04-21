use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value, AssignedCell, Region},
    dev::MockProver,
    plonk::{Circuit, Error, ConstraintSystem},
};
use halo2curves::bn256::{Fr, self};

use crate::{compression::{CompressionConfig, assignment::{INIT_STATE_ROWS, ROWS_PER_ROUND, VARS_PER_ROUND}}, spread_table::{SpreadTableChip, SpreadTableConfig, SpreadInputs}, scheduler::SchedulerConfig, chip::Columns, state::{InnerState, RoundWord, match_state_as_array}, InitializedState, MAX_ROUND};


const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

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

#[derive(Clone, Debug, Default)]
pub struct Blake2fWitness {
    pub rounds: u32,
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: [u64; 2],
    pub f: bool,
}

fn blake2f(witness: Blake2fWitness) -> ([u64; 16], [u64; 16], [u64; 8]) {
    let Blake2fWitness{ h,rounds, m, t, f} = witness;
    let (mut v0, mut v1, mut v2, mut v3, mut v4, mut v5, mut v6, mut v7) = (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    let (mut v8, mut v9, mut v10, mut v11, mut v12, mut v13, mut v14, mut v15) = (IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7]);

    v12 ^= t[0];
    v13 ^= t[1];
    v14 ^= f as u64;
    let init_state = [v0, v1, v2, v3, v4, v5, v6, v7, 
    v8, v9, v10, v11, v12, v13, v14, v15];

    for i in 0..rounds {
        let s = PRE_COMPUTED[(i as usize)%10];
        v0 += m[s[0]];
        v0 += v4;
        v12 ^= v0;
        v12 = v12.rotate_right(32);
        v8 += v12;
        v4 ^= v8;
        v4 = v4.rotate_right(24);
        v1 += m[s[1]];
        v1 += v5;
        v13 ^= v1;
        v13 = v13.rotate_right(32);
        v9 += v13;
        v5 ^= v9;
        v5 = v5.rotate_right(24);
        v2 += m[s[2]];
        v2 += v6;
        v14 ^= v2;
        v14 = v14.rotate_right(32);
        v10 += v14;
        v6 ^= v10;
        v6 = v6.rotate_right(24);
        v3 += m[s[3]];
        v3 += v7;
        v15 ^= v3;
        v15 = v15.rotate_right(32);
        v11 += v15;
        v7 ^= v11;
        v7 = v7.rotate_right(24);

        v0 += m[s[4]];
        v0 += v4;
        v12 ^= v0;
        v12 = v12.rotate_right(16);
        v8 += v12;
        v4 ^= v8;
        v4 = v4.rotate_right(63);
        v1 += m[s[5]];
        v1 += v5;
        v13 ^= v1;
        v13 = v13.rotate_right(16);
        v9 += v13;
        v5 ^= v9;
        v5 = v5.rotate_right(63);
        v2 += m[s[6]];
        v2 += v6;
        v14 ^= v2;
        v14 = v14.rotate_right(16);
        v10 += v14;
        v6 ^= v10;
        v6 = v6.rotate_right(63);
        v3 += m[s[7]];
        v3 += v7;
        v15 ^= v3;
        v15 = v15.rotate_right(16);
        v11 += v15;
        v7 ^= v11;
        v7 = v7.rotate_right(63);

        v0 += m[s[8]];
        v0 += v5;
        v15 ^= v0;
        v15 = v15.rotate_right(32);
        v10 += v15;
        v5 ^= v10;
        v5 = v5.rotate_right(24);
        v1 += m[s[9]];
        v1 += v6;
        v12 ^= v1;
        v12 = v12.rotate_right(32);
        v11 += v12;
        v6 ^= v11;
        v6 = v6.rotate_right(24);
        v2 += m[s[10]];
        v2 += v7;
        v13 ^= v2;
        v13 = v13.rotate_right(32);
        v8 += v13;
        v7 ^= v8;
        v7 = v7.rotate_right(24);
        v3 += m[s[11]];
        v3 += v4;
        v14 ^= v3;
        v14 = v14.rotate_right(32);
        v9 += v14;
        v4 ^= v9;
        v4 = v4.rotate_right(24);

        v0 += m[s[12]];
        v0 += v5;
        v15 ^= v0;
        v15 = v15.rotate_right(16);
        v10 += v15;
        v5 ^= v10;
        v5 = v5.rotate_right(63);
        v1 += m[s[13]];
        v1 += v6;
        v12 ^= v1;
        v12 = v12.rotate_right(16);
        v11 += v12;
        v6 ^= v11;
        v6 = v6.rotate_right(63);
        v2 += m[s[14]];
        v2 += v7;
        v13 ^= v2;
        v13 = v13.rotate_right(16);
        v8 += v13;
        v7 ^= v8;
        v7 = v7.rotate_right(63);
        v3 += m[s[15]];
        v3 += v4;
        v14 ^= v3;
        v14 = v14.rotate_right(16);
        v9 += v14;
        v4 ^= v9;
        v4 = v4.rotate_right(63);
    }
    let update_state = [v0, v1, v2, v3, v4, v5, v6, v7, 
    v8, v9, v10, v11, v12, v13, v14, v15];

    let mut h = h.clone();
    h[0] ^= v0 ^ v8;
    h[1] ^= v1 ^ v9;
    h[2] ^= v2 ^ v10;
    h[3] ^= v3 ^ v11;
    h[4] ^= v4 ^ v12;
    h[5] ^= v5 ^ v13;
    h[6] ^= v6 ^ v14;
    h[7] ^= v7 ^ v15;

    (init_state, update_state, h)
}

fn assert_vs(state: InnerState, vs:&[u64; 16]) {
    state.v0.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[0]));
    state.v1.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[1]));
    state.v2.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[2]));
    state.v3.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[3]));
    state.v4.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[4]));
    state.v5.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[5]));
    state.v6.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[6]));
    state.v7.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[7]));
    state.v8.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[8]));
    state.v9.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[9]));
    state.v10.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[10]));
    state.v11.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[11]));
    state.v12.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[12]));
    state.v13.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[13]));
    state.v14.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[14]));
    state.v15.unwrap().val.value_u64().map(|v| assert_eq!(v, vs[15]));
}

#[test]
fn test_round() {
    #[derive(Default)]
    pub struct MyCircuit {
        pub inputs: Blake2fWitness,
        init_state: [u64; 16],
        update_state: [u64; 16],
        outputs: [u64; 8]
    }

    #[derive(Clone, Debug)]
    pub struct CircuitConfig {
        lookup_config: SpreadTableConfig,
        compress_config: CompressionConfig,
        scheduler_config: SchedulerConfig,
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
            
            meta.enable_constant(columns.constants);
            let mut c = Vec::from([input_dense, input_spread]);
            c.push(columns.num);
            c.push(columns.round);
            c.push(columns.s_round);

            for column in c {
                meta.enable_equality(column);
            }

            let lookup = SpreadTableChip::configure(meta, input_dense, input_spread);
            let compress = CompressionConfig::configure(meta, lookup.input.clone(), columns.clone());
            let scheduler = SchedulerConfig::configure(meta, lookup.input.clone(), columns);

            CircuitConfig{
                lookup_config: lookup,
                compress_config: compress,
                scheduler_config: scheduler,
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
            
            assert_vs(init_state.state.clone(), &self.init_state);

            let update_state = layouter.assign_region(|| "assign compression round", |mut region| {
                // config.compress_config.s_global.s_add_m_and_offset_neg_12.enable(&mut region, INIT_STATE_ROWS + ROWS_PER_ROUND * 2 + 0)?;
                // config.compress_config.s_global.s_add_offset_4.enable(&mut region, INIT_STATE_ROWS + ROWS_PER_ROUND * 1 + 8 * 4)?;
                // config.compress_config.s_r1.s_xor_neg_12_rotate_32.enable(&mut region, INIT_STATE_ROWS + ROWS_PER_ROUND * 1 + 12*4)?;
                // config.compress_config.s_r1.s_xor_4_rotate_24.enable(&mut region, INIT_STATE_ROWS + ROWS_PER_ROUND * 1 + 4*4)?;
                config.compress_config.assign_round(
                    &mut region, 
                    init_state.clone(), 
                    Value::known(self.inputs.rounds as u64), 
                    self.inputs.m.iter().map(|v| Value::known(*v)).collect::<Vec<_>>().try_into().unwrap())
            })?;

            assert_vs(update_state, &self.update_state); 

            Ok(())
        }
    }

    let h = (0..8).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
    let t = (0..2).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
    let m = (0..16).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
    
    let f = fastrand::bool();

    let inputs = Blake2fWitness {
        rounds: 12,
        h: h.clone().try_into().unwrap(),
        m: m.clone().try_into().unwrap(),
        t : t.clone().try_into().unwrap(),
        f,
    };
    let (init_state, update_state, outputs) = blake2f(inputs.clone());

    let circuit: MyCircuit = MyCircuit {
        inputs,
        init_state,
        update_state,
        outputs
    };

    let prover = match MockProver::<bn256::Fr>::run(17, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_h_xor() {
    #[derive(Default)]
    pub struct MyCircuit {
        pub inputs: Blake2fWitness,
        init_state: [u64; 16],
        update_state: [u64; 16],
        outputs: [u64; 8]
    }

    #[derive(Clone, Debug)]
    pub struct CircuitConfig {
        lookup_config: SpreadTableConfig,
        compress_config: CompressionConfig,
        scheduler_config: SchedulerConfig,
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
            
            meta.enable_constant(columns.constants);
            let mut c = Vec::from([input_dense, input_spread]);
            c.push(columns.num);
            c.push(columns.round);
            c.push(columns.s_round);

            for column in c {
                meta.enable_equality(column);
            }

            let lookup = SpreadTableChip::configure(meta, input_dense, input_spread);
            let compress = CompressionConfig::configure(meta, lookup.input.clone(), columns.clone());
            let scheduler = SchedulerConfig::configure(meta, lookup.input.clone(), columns);

            CircuitConfig{
                lookup_config: lookup,
                compress_config: compress,
                scheduler_config: scheduler,
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

            let h = layouter.assign_region(|| "mock round and assign final h xor", |mut region| {
                let columns = config.compress_config.columns.clone();
                let lookup = config.compress_config.lookup.clone();
                let mut assign_v = |v: u64, row: usize| {
                    RoundWord::assign_with_lookup(
                        || "assign new state",
                        &mut region,
                        Value::known(v),
                        row,
                        columns.num,
                        &lookup,
                    )
                };
                let mut row = INIT_STATE_ROWS;
                for v in self.init_state {
                    assign_v(v, row)?;
                    row += 4;
                }

                let mut update_state = Vec::with_capacity(16);
                row += 3 * VARS_PER_ROUND + (MAX_ROUND - 1) * ROWS_PER_ROUND + 3 * VARS_PER_ROUND;
                for v in self.update_state {
                    update_state.push(assign_v(v, row)?);
                    row += 4;
                }
                let update_state:[RoundWord; 16] = update_state.try_into().unwrap();
                let update_state:InnerState = update_state.into();
                
                config.compress_config.final_h_xor(&mut region, init_state.clone(), update_state.clone())
            })?;

            h.iter().zip(self.outputs).for_each(|(h, v)| {h.map(|hv| assert_eq!(hv, v));});

            Ok(())
        }
    }

    let h = (0..8).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
    let t = (0..2).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
    let m = (0..16).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
    
    let f = fastrand::bool();
    let inputs = Blake2fWitness {
        rounds: 12,
        h: h.clone().try_into().unwrap(),
        m: m.clone().try_into().unwrap(),
        t : t.clone().try_into().unwrap(),
        f,
    };
    let (init_state, update_state, outputs) = blake2f(inputs.clone());

    let circuit: MyCircuit = MyCircuit {
        inputs,
        init_state,
        update_state,
        outputs
    };

    let prover = match MockProver::<bn256::Fr>::run(17, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}