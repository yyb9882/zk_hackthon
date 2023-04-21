use crate::{util::*, bits::AssignedBits};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
    poly::Rotation,
};
use halo2curves::{pasta::pallas, bn256};
use std::convert::TryInto;
use std::marker::PhantomData;


// TODO: remove tag
/// An input word into a lookup, containing (tag, dense, spread)
#[derive(Copy, Clone, Debug)]
pub(super) struct SpreadWord<const DENSE: usize, const SPREAD: usize> {
    pub dense: [bool; DENSE],
    pub spread: [bool; SPREAD],
}


impl<const DENSE: usize, const SPREAD: usize> SpreadWord<DENSE, SPREAD> {
    pub(super) fn new(dense: [bool; DENSE]) -> Self {
        assert!(DENSE <= 16);
        SpreadWord {
            dense,
            spread: spread_bits(dense),
        }
    }

    #[allow(dead_code)]
    pub(super) fn try_new<T: TryInto<[bool; DENSE]> + std::fmt::Debug>(dense: T) -> Self
    where
        <T as TryInto<[bool; DENSE]>>::Error: std::fmt::Debug,
    {
        assert!(DENSE <= 16);
        let dense: [bool; DENSE] = dense.try_into().unwrap();
        SpreadWord {
            dense,
            spread: spread_bits(dense),
        }
    }
}

/// A variable stored in advice columns corresponding to a row of [`SpreadTableConfig`].
#[derive(Clone, Debug)]
pub struct SpreadVar<const DENSE: usize, const SPREAD: usize> {
    pub dense: AssignedBits<DENSE>,
    pub spread: AssignedBits<SPREAD>,
}

impl<const DENSE: usize, const SPREAD: usize> SpreadVar<DENSE, SPREAD> {
    pub(super) fn with_lookup(
        region: &mut Region<'_, bn256::Fr>,
        cols: &SpreadInputs,
        row: usize,
        word: Value<SpreadWord<DENSE, SPREAD>>,
    ) -> Result<Self, Error> {
        let dense_val = word.map(|word| word.dense);
        let spread_val = word.map(|word| word.spread);

        let dense =
            AssignedBits::<DENSE>::assign_bits(region, || "dense", cols.dense, row, dense_val)?;

        let spread =
            AssignedBits::<SPREAD>::assign_bits(region, || "spread", cols.spread, row, spread_val)?;

        Ok(SpreadVar { dense, spread })
    }

    #[allow(dead_code)]
    pub(super) fn without_lookup(
        region: &mut Region<'_, bn256::Fr>,
        dense_col: Column<Advice>,
        dense_row: usize,
        spread_col: Column<Advice>,
        spread_row: usize,
        word: Value<SpreadWord<DENSE, SPREAD>>,
    ) -> Result<Self, Error> {
        let dense_val = word.map(|word| word.dense);
        let spread_val = word.map(|word| word.spread);

        let dense = AssignedBits::<DENSE>::assign_bits(
            region,
            || "dense",
            dense_col,
            dense_row,
            dense_val,
        )?;

        let spread = AssignedBits::<SPREAD>::assign_bits(
            region,
            || "spread",
            spread_col,
            spread_row,
            spread_val,
        )?;

        Ok(SpreadVar { dense, spread })
    }
}

#[derive(Clone, Debug)]
pub struct SpreadInputs {
    pub(super) dense: Column<Advice>,
    pub(super) spread: Column<Advice>,
}

#[derive(Clone, Debug)]
pub(super) struct SpreadTable {
    pub(super) dense: TableColumn,
    pub(super) spread: TableColumn,
}

#[derive(Clone, Debug)]
pub(super) struct SpreadTableConfig {
    pub input: SpreadInputs,
    pub table: SpreadTable,
}

#[derive(Clone, Debug)]
pub(super) struct SpreadTableChip<F: FieldExt> {
    config: SpreadTableConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for SpreadTableChip<F> {
    type Config = SpreadTableConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> SpreadTableChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        input_dense: Column<Advice>,
        input_spread: Column<Advice>,
    ) -> <Self as Chip<F>>::Config {
        let table_dense = meta.lookup_table_column();
        let table_spread = meta.lookup_table_column();

        meta.lookup("lookup", |meta| {
            let dense_cur = meta.query_advice(input_dense, Rotation::cur());
            let spread_cur = meta.query_advice(input_spread, Rotation::cur());

            vec![
                (dense_cur, table_dense),
                (spread_cur, table_spread),
            ]
        });

        SpreadTableConfig {
            input: SpreadInputs {
                dense: input_dense,
                spread: input_spread,
            },
            table: SpreadTable {
                dense: table_dense,
                spread: table_spread,
            },
        }
    }

    pub fn load(
        config: SpreadTableConfig,
        layouter: &mut impl Layouter<F>,
    ) -> Result<<Self as Chip<F>>::Loaded, Error> {
        layouter.assign_table(
            || "spread table",
            |mut table| {
                // We generate the row values lazily (we only need them during keygen).
                let mut rows = SpreadTableConfig::generate::<F>();

                for index in 0..(1 << 16) {
                    let mut row = None;
                    row = rows.next();
                    table.assign_cell(
                        || "dense",
                        config.table.dense,
                        index,
                        || Value::known(row.map(|(dense, _)| dense).unwrap()),
                    )?;
                    table.assign_cell(
                        || "spread",
                        config.table.spread,
                        index,
                        || Value::known(row.map(|(_, spread)| spread).unwrap()),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl SpreadTableConfig {
    fn generate<F: FieldExt>() -> impl Iterator<Item = (F, F)> {
        (1..=(1 << 16)).scan(
            (F::zero(), F::zero()),
            |(dense, spread), i| {
                // We computed this table row in the previous iteration.
                let res = (*dense, *spread);

                // i holds the zero-indexed row number for the next table row.
                *dense += F::one();
                if i & 1 == 0 {
                    // On even-numbered rows we recompute the spread.
                    *spread = F::zero();
                    for b in 0..16 {
                        if (i >> b) & 1 != 0 {
                            *spread += F::from(1 << (2 * b));
                        }
                    }
                } else {
                    // On odd-numbered rows we add one.
                    *spread += F::one();
                }

                Some(res)
            },
        )
    }
}
