#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

use halo2_exp::{Blake2fChip, Blake2fConfig};

use halo2_proofs::{
    circuit::Layouter,
    plonk::Error,
};

#[derive(Clone, Debug, Default)]
pub struct Blake2fWitness {
    pub rounds: u32,
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: [u64; 2],
    pub f: bool,
}

#[cfg(any(feature = "test", test))]
pub mod dev {
    use super::*;

    use ethers_core::{types::H512, utils::hex::FromHex};
    use halo2_exp::Blake2fInstructions;
    use halo2_proofs::{circuit::{SimpleFloorPlanner, Value}, plonk::Circuit, halo2curves::bn256};
    use std::{marker::PhantomData, str::FromStr};

    lazy_static::lazy_static! {
        // https://eips.ethereum.org/EIPS/eip-152#example-usage-in-solidity
        pub static ref INPUTS_OUTPUTS: (Vec<Blake2fWitness>, Vec<H512>) = {
            let (h1, h2) = (
                <[u8; 32]>::from_hex("48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5").expect(""),
                <[u8; 32]>::from_hex("d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b").expect(""),
            );
            let (m1, m2, m3, m4) = (
                <[u8; 32]>::from_hex("6162630000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
                <[u8; 32]>::from_hex("0000000000000000000000000000000000000000000000000000000000000000").expect(""),
            );
            (
                vec![
                    Blake2fWitness {
                        rounds: 12,
                        h: [
                            u64::from_le_bytes(h1[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(h1[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(h1[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(h1[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(h2[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(h2[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(h2[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(h2[0x18..0x20].try_into().expect("")),
                        ],
                        m: [
                            u64::from_le_bytes(m1[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m1[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m1[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m1[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m2[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m2[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m2[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m2[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m3[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m3[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m3[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m3[0x18..0x20].try_into().expect("")),
                            u64::from_le_bytes(m4[0x00..0x08].try_into().expect("")),
                            u64::from_le_bytes(m4[0x08..0x10].try_into().expect("")),
                            u64::from_le_bytes(m4[0x10..0x18].try_into().expect("")),
                            u64::from_le_bytes(m4[0x18..0x20].try_into().expect("")),
                        ],
                        t: [3, 0],
                        f: true,
                    }
                ],
                vec![
                    H512::from_str("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
                    .expect("BLAKE2F compression function output is 64-bytes")
                ],
            )
        };
    }

    #[derive(Default)]
    pub struct Blake2fTestCircuit<F> {
        pub inputs: Vec<Blake2fWitness>,
        pub outputs: Vec<H512>,
        pub _marker: PhantomData<F>,
    }

    impl Circuit<bn256::Fr> for Blake2fTestCircuit<bn256::Fr> {
        type Config = Blake2fConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<bn256::Fr>) -> Self::Config {
            Blake2fChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<bn256::Fr>,
        ) -> Result<(), Error> {
            let blake2f_chip = Blake2fChip::construct(config);
            blake2f_chip.initialize(&mut layouter)?;

            for (input, output) in self.inputs.iter().zip(self.outputs.iter()) {
                let f = if input.f {
                    0xFFFFFFFFFFFFFFFF_u64
                }else {
                    0
                };
                let h = blake2f_chip.compress(
                    &mut layouter, 
                    input.h.iter().map(|v| Value::known(*v)).collect::<Vec<_>>().try_into().unwrap(),
                    input.m.iter().map(|v| Value::known(*v)).collect::<Vec<_>>().try_into().unwrap(),
                    Value::known(input.t[0]),
                    Value::known(input.t[1]),
                    Value::known(f),
                    Value::known(input.rounds as u64),
                )?;

                let mut ex_h = Vec::with_capacity(8);
                for hi in output.0.chunks(8) {
                    let mut hi = hi.to_vec();
                    hi.reverse();
                    let mut sum = 0_u64;
                    for hi in hi[..7].iter() {
                        sum += *hi as u64;
                        sum <<= 8;
                    }
                    sum += hi[7] as u64;
                    ex_h.push(sum);
                }

                h.iter().zip(ex_h).for_each(|(h, ex_h)|{
                    h.map(|v| assert_eq!(v, ex_h));
                });
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{dev::MockProver, halo2curves::{bn256::Fr}};
    use std::marker::PhantomData;

    use crate::dev::{Blake2fTestCircuit, INPUTS_OUTPUTS};

    #[test]
    fn test_blake2f_circuit() {
        let (inputs, outputs) = INPUTS_OUTPUTS.clone();

        let circuit: Blake2fTestCircuit<Fr> = Blake2fTestCircuit {
            inputs,
            outputs,
            _marker: PhantomData,
        };

        let k = 17;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
