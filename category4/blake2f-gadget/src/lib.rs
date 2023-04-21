use std::{fmt::Debug, marker::PhantomData};

use halo2_proofs::{
    circuit::{Chip, Layouter, AssignedCell, Value},
    plonk::Error,
};
use halo2curves::{FieldExt, bn256::Fr};

mod spread_table;
mod bits;
mod util;
mod chip;
mod compression;
mod scheduler;
mod state;

pub use chip::{Blake2fChip, Blake2fConfig};

use state::InnerState;


pub(crate) const MAX_ROUND: usize = 12;

pub struct Blake2f<F: FieldExt, CS: Blake2fInstructions<F>> {
    chip: CS,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, Blake2fChip: Blake2fInstructions<F>> Blake2f<F, Blake2fChip> {
    pub fn new(chip: Blake2fChip, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
        chip.initialize(&mut layouter)?;
        Ok(Self {
            chip,
            _marker: PhantomData,
        })
    }

    pub fn compress(
        &mut self,
        layouter: &mut impl Layouter<F>,
        h: [Blake2fChip::CSU64; 8],
        m: [Blake2fChip::CSU64; 16],
        c0: Blake2fChip::CSU64,
        c1: Blake2fChip::CSU64,
        flag: Blake2fChip::CSU64,
        rounds: Blake2fChip::CSU64,
    ) -> Result<[Blake2fChip::CSU64; 8], Error>{
        self.chip.compress(layouter, h, m, c0, c1, flag, rounds)
    }
}

#[derive(Debug, Clone)]
pub struct InitializedState {
    pub state: InnerState,
    pub m: [AssignedCell<Fr, Fr>; 16],
    pub round: AssignedCell<Fr, Fr>,
}

#[derive(Debug, Clone)]
pub struct Blake2fDigest {
    pub h: [Value<u64>; 8],
}

pub trait Blake2fInstructions<F: FieldExt>: Chip<F> {
    type CSU64: Clone + Debug + Default;

    fn initialize(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;

    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        h: [Self::CSU64; 8],
        m: [Self::CSU64; 16],
        c0: Self::CSU64,
        c1: Self::CSU64,
        flag: Self::CSU64,
        rounds: Self::CSU64,
    ) -> Result<[Self::CSU64; 8], Error>;
}

