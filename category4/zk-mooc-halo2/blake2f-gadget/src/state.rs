use halo2_proofs::{circuit::{Value, Region}, plonk::{Column, Advice, Error}};
use halo2curves::{pasta::pallas, bn256};

use crate::{bits::AssignedBits, spread_table::{SpreadWord, SpreadInputs, SpreadVar}, chip::Columns};
use crate::util::*;

#[derive(Clone, Debug)]
pub struct InnerState {
    pub v0: Option<RoundWord>,
    pub v1: Option<RoundWord>,
    pub v2: Option<RoundWord>,
    pub v3: Option<RoundWord>,
    pub v4: Option<RoundWord>,
    pub v5: Option<RoundWord>,
    pub v6: Option<RoundWord>,
    pub v7: Option<RoundWord>,
    pub v8: Option<RoundWord>,
    pub v9: Option<RoundWord>,
    pub v10: Option<RoundWord>,
    pub v11: Option<RoundWord>,
    pub v12: Option<RoundWord>,
    pub v13: Option<RoundWord>,
    pub v14: Option<RoundWord>,
    pub v15: Option<RoundWord>,
}

impl InnerState {
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        v0: RoundWord,
        v1: RoundWord,
        v2: RoundWord,
        v3: RoundWord,
        v4: RoundWord,
        v5: RoundWord,
        v6: RoundWord,
        v7: RoundWord,
        v8: RoundWord,
        v9: RoundWord,
        v10: RoundWord,
        v11: RoundWord,
        v12: RoundWord,
        v13: RoundWord,
        v14: RoundWord,
        v15: RoundWord,
    ) -> Self {
        InnerState {
            v0: Some(v0),
            v1: Some(v1),
            v2: Some(v2),
            v3: Some(v3),
            v4: Some(v4),
            v5: Some(v5),
            v6: Some(v6),
            v7: Some(v7),
            v8: Some(v8),
            v9: Some(v9),
            v10: Some(v10),
            v11: Some(v11),
            v12: Some(v12),
            v13: Some(v13),
            v14: Some(v14),
            v15: Some(v15),
        }
    }

    pub fn empty_state() -> Self {
        Self {
            v0: None,
            v1: None,
            v2: None,
            v3: None,
            v4: None,
            v5: None,
            v6: None,
            v7: None,
            v8: None,
            v9: None,
            v10: None,
            v11: None,
            v12: None,
            v13: None,
            v14: None,
            v15: None,
        }
    }
}

impl From<[RoundWord; 16]> for InnerState {
    fn from(value: [RoundWord; 16]) -> Self {
        Self::new(value[0].clone(), value[1].clone(), value[2].clone(), value[3].clone(), value[4].clone(), value[5].clone(), value[6].clone(), value[7].clone(), value[8].clone(), value[9].clone(), value[10].clone(), value[11].clone(), value[12].clone(), value[13].clone(), value[14].clone(), value[15].clone())
    }
}

#[allow(clippy::many_single_char_names, dead_code)]
pub fn match_state(
    state: InnerState,
) -> (
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
    RoundWord,
) {
    (
        state.v0.unwrap(),
        state.v1.unwrap(),
        state.v2.unwrap(),
        state.v3.unwrap(),
        state.v4.unwrap(),
        state.v5.unwrap(),
        state.v6.unwrap(),
        state.v7.unwrap(),
        state.v8.unwrap(),
        state.v9.unwrap(),
        state.v10.unwrap(),
        state.v11.unwrap(),
        state.v12.unwrap(),
        state.v13.unwrap(),
        state.v14.unwrap(),
        state.v15.unwrap(),
    )
}


#[allow(clippy::many_single_char_names)]
pub fn match_state_as_array(
    state: InnerState,
) -> [RoundWord; 16] {
    [
        state.v0.unwrap(),
        state.v1.unwrap(),
        state.v2.unwrap(),
        state.v3.unwrap(),
        state.v4.unwrap(),
        state.v5.unwrap(),
        state.v6.unwrap(),
        state.v7.unwrap(),
        state.v8.unwrap(),
        state.v9.unwrap(),
        state.v10.unwrap(),
        state.v11.unwrap(),
        state.v12.unwrap(),
        state.v13.unwrap(),
        state.v14.unwrap(),
        state.v15.unwrap(),
    ]
}

#[derive(Clone, Debug)]
pub struct RoundWord {
    pub val: AssignedBits<64>,
    pub halves: Option<[SpreadVar<16, 32>; 4]>,
}

impl RoundWord {
    pub fn new(val: AssignedBits<64>, halves: Option<[SpreadVar<16, 32>; 4]>) -> Self {
        RoundWord {
            val,
            halves,
        }
    }


    pub fn copy_into_without_lookup(&self, region: &mut Region<'_, bn256::Fr>, offset: usize, columns: &Columns) -> Result<Self, Error> {
        let new_val = Self::assign_without_lookup(|| "copy roundword", region, self.val.value_u64(), offset, columns.num)?;
        region.constrain_equal(new_val.val.cell(), self.val.cell());

        Ok(new_val)
    }

    pub fn copy_into_with_lookup(&self, region: &mut Region<'_, bn256::Fr>, offset: usize, columns: &Columns, lookup: &SpreadInputs) -> Result<Self, Error> {
        let new_val = Self::assign_with_lookup(|| "copy roundword", region, self.val.value_u64(), offset, columns.num, lookup)?;
        region.constrain_equal(new_val.val.cell(), self.val.cell());

        Ok(new_val)
    }

    pub fn assign_without_lookup<A: Fn()-> AR, AR: Into<String>>(
        annotation: A,
        region: &mut Region<'_, bn256::Fr>,
        val: Value<u64>,
        offset: usize,
        num_col: Column<Advice>,
    ) -> Result<Self, Error> {
        let val = AssignedBits::<64>::assign(
            region,
            || format!("{}-val", annotation().into()),
            num_col,
            offset,
            val,
        )?;

        Ok(Self {
            val,
            halves: None,
        })
    }

    pub(super) fn assign_with_lookup<A: Fn()-> AR, AR: Into<String>>(
        annotation: A,
        region: &mut Region<'_, bn256::Fr>,
        val: Value<u64>,
        offset: usize,
        num_col: Column<Advice>,
        lookup: &SpreadInputs,
    ) -> Result<Self, Error> {
        let mut v = 0;
        val.map(|x| {
            v = x;
            x
        });

        let bits: [_; 64] = i2lebsp(v);

        let d0: [bool; 16] = bits[..16].try_into().unwrap();
        let d1: [bool; 16] = bits[16..32].try_into().unwrap();
        let d2: [bool; 16] = bits[32..48].try_into().unwrap();
        let d3: [bool; 16] = bits[48..].try_into().unwrap();

        let annotation = annotation().into();
        let dences = [d0, d1, d2, d3];

        let val = AssignedBits::<64>::assign(
            region,
            || format!("{}-val", annotation),
            num_col,
            offset,
            val,
        )?;

        let mut halves = Vec::new();
        for i in 0..4 {
            let sw = SpreadWord::<16, 32>::new(dences[i]);
            let s = SpreadVar::with_lookup(region, lookup, offset + i, Value::known(sw))?;
            halves.push(s);
        }

        Ok(Self {
            val,
            halves: Some(halves.try_into().unwrap())
        })
    }

}

// lo to hi
#[derive(Clone, Debug)]
pub struct RoundWordDense(AssignedBits<16>, AssignedBits<16>, AssignedBits<16>, AssignedBits<16>);

impl RoundWordDense {
    pub fn copy_into(
        &self,
        region: &mut Region<'_, bn256::Fr>,
        dense_columns: [Column<Advice>; 4],
        row: usize,
    ) -> Result<Self, Error> {
        let d0 = self.0.copy_advice(|| "copy dense 0", region, dense_columns[0], row).map(AssignedBits)?;
        let d1 = self.1.copy_advice(|| "copy dense 1", region, dense_columns[1], row).map(AssignedBits)?;
        let d2 = self.2.copy_advice(|| "copy dense 2", region, dense_columns[2], row).map(AssignedBits)?;
        let d3 = self.3.copy_advice(|| "copy dense 3", region, dense_columns[3], row).map(AssignedBits)?;
        Ok(RoundWordDense(d0, d1, d2, d3))
    }
}

impl From<(AssignedBits<16>, AssignedBits<16>, AssignedBits<16>, AssignedBits<16>)> for RoundWordDense {
    fn from(halves: (AssignedBits<16>, AssignedBits<16>, AssignedBits<16>, AssignedBits<16>)) -> Self {
        Self(halves.0, halves.1, halves.2, halves.3)
    }
}

impl From<[AssignedBits<16>; 4]> for RoundWordDense {
    fn from(halves: [AssignedBits<16>; 4]) -> Self {
        Self(halves[0].clone(), halves[1].clone(), halves[2].clone(), halves[3].clone())
    }
}

impl RoundWordDense {
    //TODO: test
    pub fn value(&self) -> Value<u64> {
        self.0
            .value_u16()
            .zip(self.1.value_u16())
            .zip(self.2.value_u16())
            .zip(self.3.value_u16())
            .map(|(((n0, n1), n2), n3)|
                n0 as u64
                + (1 << 16) * n1 as u64
                + (1 << 32) * n2 as u64
                + (1 << 48) * n3 as u64
            )
    }
}

#[derive(Clone, Debug)]
pub struct RoundWordSpread(AssignedBits<32>, AssignedBits<32>, AssignedBits<32>, AssignedBits<32>);

impl RoundWordSpread {
    pub fn copy_into(
        &self,
        region: &mut Region<'_, bn256::Fr>,
        spread_columns: [Column<Advice>; 4],
        row: usize,
    ) -> Result<Self, Error> {
        let s0 = self.0.copy_advice(|| "copy spread 0", region, spread_columns[0], row).map(AssignedBits)?;
        let s1 = self.1.copy_advice(|| "copy spread 1", region, spread_columns[1], row).map(AssignedBits)?;
        let s2 = self.2.copy_advice(|| "copy spread 2", region, spread_columns[2], row).map(AssignedBits)?;
        let s3 = self.3.copy_advice(|| "copy spread 3", region, spread_columns[3], row).map(AssignedBits)?;
        Ok(Self(s0, s1, s2, s3))
    }
}

impl From<(AssignedBits<32>, AssignedBits<32>, AssignedBits<32>, AssignedBits<32>)> for RoundWordSpread {
    fn from(halves: (AssignedBits<32>, AssignedBits<32>, AssignedBits<32>, AssignedBits<32>)) -> Self {
        Self(halves.0, halves.1, halves.2, halves.3)
    }
}

impl From<[AssignedBits<32>; 4]> for RoundWordSpread {
    fn from(halves: [AssignedBits<32>; 4]) -> Self {
        Self(halves[0].clone(), halves[1].clone(), halves[2].clone(), halves[3].clone())
    }
}

impl RoundWordSpread {
    //TODO: add test
    pub fn value(&self) -> Value<u128> {
        self.0
            .value_u32()
            .zip(self.1.value_u32())
            .zip(self.2.value_u32())
            .zip(self.3.value_u32())
            .map(|(((n0, n1), n2), n3)|
                n0 as u128
                + (1 << 32) * n1 as u128
                + (1 << 64) * n2 as u128
                + (1 << 96) * n3 as u128
            )

    }
}
