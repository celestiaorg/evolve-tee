use dcap_qvl::QuoteCollateralV3;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Inputs {
    pub quote: Vec<u8>,
    pub event_log: Vec<u8>,
    pub report_data: Vec<u8>,
    pub collateral: QuoteCollateralV3,
    pub now: u64,
}
