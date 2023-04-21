use std::fmt::Debug;
use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Chip, Value},
    plonk::{Error, Column, Advice, ConstraintSystem, Fixed, VirtualCells, Expression}, poly::Rotation,
};
use halo2_proofs::circuit::Layouter;

use halo2curves::{FieldExt, bn256::{self, Fr}};

use crate::{compression::CompressionConfig, spread_table::SpreadInputs};
use crate::scheduler::SchedulerConfig;
use crate::{Blake2fInstructions, spread_table::{SpreadTableChip, SpreadTableConfig}};

#[derive(Clone, Debug)]
pub struct Blake2fChip {
    config: Blake2fConfig,
    _marker: PhantomData<bn256::Fr>,
}

// TODO: check generic
impl Blake2fInstructions<bn256::Fr> for  Blake2fChip {
    type CSU64 = Value<u64>;

    fn initialize(&self, layouter: &mut impl Layouter<bn256::Fr>) -> Result<(), Error> {
        Self::load(&self.config, layouter)
    }

    fn compress(
        &self,
        layouter: &mut impl halo2_proofs::circuit::Layouter<bn256::Fr>,
        h: [Self::CSU64; 8],
        m: [Self::CSU64; 16],
        c0: Self::CSU64,
        c1: Self::CSU64,
        flag: Self::CSU64,
        rounds: Self::CSU64,
    ) -> Result<[Self::CSU64; 8], Error> {
        let init_state = self.config.scheduler.process(layouter, h, m, c0, c1, flag, rounds)?;
        self.config.compression.compress(layouter, init_state, rounds, m)
    }
}

impl Chip<bn256::Fr> for Blake2fChip {
    type Config = Blake2fConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}


#[derive(Clone, Debug)]
pub struct Blake2fConfig {
    lookup: SpreadTableConfig,
    scheduler: SchedulerConfig,
    compression: CompressionConfig,
}


impl Blake2fChip {
    pub fn construct(config: <Self as Chip<bn256::Fr>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<bn256::Fr>,
    ) -> <Self as Chip<bn256::Fr>>::Config {
        let columns = Columns::init(meta);

        let input_dense = meta.advice_column();
        let input_spread = meta.advice_column();

        for column in [input_dense, input_spread] {
            meta.enable_equality(column);
        }

        let lookup = SpreadTableChip::configure(meta, input_dense, input_spread);
        let lookup_inputs = lookup.input.clone();

        let compression = CompressionConfig::configure(meta, lookup_inputs.clone(), columns.clone());
        let scheduler = SchedulerConfig::configure(meta, lookup_inputs, columns);

        Blake2fConfig { lookup, scheduler, compression }
    }

    pub fn load(
        config: &Blake2fConfig,
        layouter: &mut impl Layouter<bn256::Fr>,
    ) -> Result<(), Error> {
        SpreadTableChip::load(config.lookup.clone(), layouter)
    }
}

#[derive(Debug, Clone)]
pub struct Columns {
    pub num: Column<Advice>,
    pub constants: Column<Fixed>,
    pub round: Column<Advice>,
    pub s_round: Column<Advice>,
}

impl Columns {
    pub fn init(
        meta: &mut ConstraintSystem<bn256::Fr>,
    ) -> Self {
        let num = meta.advice_column();

        let s_round = meta.advice_column();
        let round = meta.advice_column();

        let constants = meta.fixed_column();


        for c in [num, s_round, round] {
            meta.enable_equality(c);
        }

        meta.enable_constant(constants);

        Self { num, constants, round, s_round }
    }
}

pub(crate) fn spread_bits_num(bits: &[usize]) -> Vec<usize> {
    bits.iter().map(|num| *num * 2).collect::<Vec<_>>()
}

pub(crate) fn query_table(
    meta: &mut VirtualCells<bn256::Fr>,
    lookup: &SpreadInputs,
    rotation: Rotation,
) -> ([Expression<bn256::Fr>; 4], [Expression<bn256::Fr>; 4]) {
    let mut dense = Vec::new();
    let mut spreads = Vec::new();

    for i in 0..4 {
         dense.push(meta.query_advice(lookup.dense, Rotation(rotation.0 + i)));
         spreads.push(meta.query_advice(lookup.spread, Rotation(rotation.0 + i)));
    }

    (dense.try_into().unwrap(), spreads.try_into().unwrap())
}

// little endian
//            lo          hi
// bits_num :[16, 16, 16, 16]
// bits     :[ a,  b,  c,  d,]
// r = a + b * 2^16 + c * 2^32 + d * 2^48
pub(crate) fn compose_val_from_bits_num(
    bits: &[Expression<bn256::Fr>],
    bits_num: &[usize],
) -> Expression<bn256::Fr> {
    assert_eq!(bits.len(), bits_num.len());

    bits.into_iter()
        .enumerate()
        .fold(Expression::Constant(Fr::from(0)), |sum, (i, bits)| {
            let space = bits_num[..i].iter().sum::<usize>();
            sum + (*bits).clone() * Expression::Constant(Fr::from_u128(1 << space))
        })
}

// little endian
pub(crate) fn compose_spread_from_bits(
    spread_bits: &[Expression<bn256::Fr>],
) -> Expression<bn256::Fr> {
    if spread_bits.len() == 1 {
        return spread_bits[0].clone();
    }

    compose_val_from_bits_num(&spread_bits, &spread_bits_num(&[16, 16, 16, 16]))
}

pub(crate) fn compose_dense_from_bits(
    dense_bits: &[Expression<bn256::Fr>],
) -> Expression<bn256::Fr> {
    compose_val_from_bits_num(&dense_bits, &[16, 16, 16, 16])
}

// little endian
pub(crate) fn compose_spread_from_rotate_bits<const SPACE: usize>(
    spread_bits: &[Expression<bn256::Fr>],
) -> Expression<bn256::Fr> {
    assert!(SPACE == 16 || SPACE == 32 || SPACE == 24 || SPACE == 63);

    let mut spread_bits_num = if SPACE == 16 {
        spread_bits_num(&[16, 48])
    } else if SPACE == 32 {
        spread_bits_num(&[32, 32])
    } else if SPACE == 24 {
        spread_bits_num(&[24, 40])
    } else if SPACE == 63 {
        spread_bits_num(&[63, 1])
    } else {
        Vec::new()
    };

    let mut spread_bits = spread_bits.to_vec();

    compose_val_from_bits_num(&spread_bits, &spread_bits_num)
}


#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, Error, ConstraintSystem, Instance},
    };

    use crate::bits::AssignedBits;

    use super::*;

    #[test]
    fn test_whole() {
        #[derive(Clone, Debug, Default)]
        pub struct Blake2fWitness {
            pub rounds: u32,
            pub h: [u64; 8],
            pub m: [u64; 16],
            pub t: [u64; 2],
            pub f: bool,
        }

        #[derive(Default)]
        pub struct MyCircuit {
            pub inputs: Blake2fWitness,
            pub outputs: [u64; 8]
        }

        impl Circuit<bn256::Fr> for MyCircuit {
            type Config = Blake2fConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<bn256::Fr>) -> Self::Config {
                Blake2fChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<bn256::Fr>,
            ) -> Result<(), Error> {
                let blake2f_chip = Blake2fChip::construct(config);
                blake2f_chip.initialize(&mut layouter)?;
                let f = if self.inputs.f {
                    0xFFFFFFFFFFFFFFFF_u64
                }else {
                    0
                };
                let h = blake2f_chip.compress(
                    &mut layouter,
                    self.inputs.h.iter().map(|v| Value::known(*v)).collect::<Vec<_>>().try_into().unwrap(),
                    self.inputs.m.iter().map(|v| Value::known(*v)).collect::<Vec<_>>().try_into().unwrap(),
                    Value::known(self.inputs.t[0]),
                    Value::known(self.inputs.t[1]),
                    Value::known(f),
                    Value::known(self.inputs.rounds as u64),
                )?;

                h.iter().enumerate().for_each(|(i, h)| {
                    h.map(|v|
                        if v != self.outputs[i] {
                            println!("i :{i} v:{:?}, outputs:{:?}", v, self.outputs[i]);
                        }
                    );
                });

                Ok(())
            }
        }

        let h =
        [0x6a09e667f2bdc948_u64, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
        let m = [0x0000000000636261, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000];
        let t = [3,0];
        let f = true;
        let rounds = 12;
        let outputs = [0x0D4D1C983FA580BA_u64, 0xE9F6129FB697276A, 0xB7C45A68142F214C,
        0xD1A2FFDB6FBB124B, 0x2D79AB2A39C5877D, 0x95CC3345DED552C2,
        0x5A92F1DBA88AD318, 0x239900D4ED8623B9];

        // let h = (0..8).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
        // let t = (0..2).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
        // let m = (0..16).map(|_| fastrand::u64(..)).collect::<Vec<_>>();
        // let f = fastrand::bool();
        let circuit: MyCircuit = MyCircuit {
            inputs: Blake2fWitness {
                rounds,
                h,
                m,
                t,
                f,
            },
            outputs,
        };

        let prover = match MockProver::<bn256::Fr>::run(17, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
