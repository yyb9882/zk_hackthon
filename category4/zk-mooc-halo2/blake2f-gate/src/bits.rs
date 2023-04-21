use halo2curves::{pasta::pallas, bn256};

use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Any, Assigned, Column, Error},
};

use crate::util::*;


//TODO: u32 Bits to u64 Bits

#[derive(Clone, Debug)]
/// Little-endian bits (up to 64 bits)
pub struct Bits<const LEN: usize>([bool; LEN]);

impl<const LEN: usize> Bits<LEN> {
    #[allow(dead_code)]
    fn spread<const SPREAD: usize>(&self) -> [bool; SPREAD] {
        spread_bits(self.0)
    }
}

impl<const LEN: usize> std::ops::Deref for Bits<LEN> {
    type Target = [bool; LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> From<[bool; LEN]> for Bits<LEN> {
    fn from(bits: [bool; LEN]) -> Self {
        Self(bits)
    }
}

impl<const LEN: usize> From<&Bits<LEN>> for [bool; LEN] {
    fn from(bits: &Bits<LEN>) -> Self {
        bits.0
    }
}

impl<const LEN: usize> From<&Bits<LEN>> for Assigned<bn256::Fr> {
    fn from(bits: &Bits<LEN>) -> Assigned<bn256::Fr> {
        assert!(LEN <= 64);
        bn256::Fr::from(lebs2ip(&bits.0)).into()
    }
}

impl From<&Bits<16>> for u16 {
    fn from(bits: &Bits<16>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<16> {
    fn from(int: u16) -> Bits<16> {
        Bits(i2lebsp::<16>(int.into()))
    }
}

impl From<&Bits<32>> for u32 {
    fn from(bits: &Bits<32>) -> u32 {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<32> {
    fn from(int: u32) -> Bits<32> {
        Bits(i2lebsp::<32>(int.into()))
    }
}

impl From<&Bits<64>> for u64 {
    fn from(bits: &Bits<64>) -> u64 {
        lebs2ip(&bits.0)
    }
}

impl From<u64> for Bits<64> {
    fn from(int: u64) -> Bits<64> {
        Bits(i2lebsp::<64>(int.into()))
    }
}

#[derive(Clone, Debug)]
pub struct AssignedBits<const LEN: usize>(pub AssignedCell<Bits<LEN>, bn256::Fr>);

impl<const LEN: usize> std::ops::Deref for AssignedBits<LEN> {
    type Target = AssignedCell<Bits<LEN>, bn256::Fr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> AssignedBits<LEN> {
    pub(crate) fn assign_bits<A, AR, T: TryInto<[bool; LEN]> + std::fmt::Debug + Clone>(
        region: &mut Region<'_, bn256::Fr>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<T>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
        <T as TryInto<[bool; LEN]>>::Error: std::fmt::Debug,
    {
        let value: Value<[bool; LEN]> = value.map(|v| v.try_into().unwrap());
        let value: Value<Bits<LEN>> = value.map(|v| v.into());

        let column: Column<Any> = column.into();
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl AssignedBits<16> {
    pub(crate) fn value_u16(&self) -> Value<u16> {
        self.value().map(|v| v.into())
    }

    #[allow(dead_code)]
    pub(crate) fn assign<A, AR>(
        region: &mut Region<'_, bn256::Fr>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u16>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<16>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl AssignedBits<32> {
    pub(crate) fn value_u32(&self) -> Value<u32> {
        self.value().map(|v| v.into())
    }

    #[allow(dead_code)]
    pub(crate) fn assign<A, AR>(
        region: &mut Region<'_, bn256::Fr>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u32>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<32>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}


impl AssignedBits<64> {
    pub(crate) fn value_u64(&self) -> Value<u64> {
        self.value().map(|v| v.into())
    }

    pub(crate) fn assign<A, AR>(
        region: &mut Region<'_, bn256::Fr>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u64>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<64>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}
