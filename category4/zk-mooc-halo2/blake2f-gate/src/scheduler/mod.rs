pub mod gates;
pub mod assignment;

pub use gates::*;

use halo2_proofs::plonk::Selector;

use crate::spread_table::SpreadInputs;
use crate::chip::Columns;

#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    pub lookup: SpreadInputs,
    pub columns: Columns,
    pub s_decompose: Selector,
    pub s_xor_v12_v13_v14: Selector,
}
