use dcap_qvl::QuoteCollateralV3;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

#[derive(Serialize, Deserialize)]
pub struct Inputs {
    pub quote: Vec<u8>,
    pub event_log: Vec<u8>,
    pub report_data: Vec<u8>,
    pub output: Vec<u8>,
    pub collateral: QuoteCollateralV3,
    pub now: u64,
}

pub fn validate_tcb(report: &VerifiedReport) {
    fn validate_td10(report: &TDReport10) {
        let is_debug = report.td_attributes[0] & 0x01 != 0;
        if is_debug {
            panic!("Debug mode is not allowed");
        }
        if report.mr_signer_seam != [0u8; 48] {
            panic!("Invalid mr signer seam");
        }
    }
    fn validate_td15(report: &TDReport15) {
        if report.mr_service_td != [0u8; 48] {
            panic!("Invalid mr service td");
        }
        validate_td10(&report.base)
    }
    fn validate_sgx(report: &EnclaveReport) {
        let is_debug = report.attributes[0] & 0x02 != 0;
        if is_debug {
            panic!("Debug mode is not allowed");
        }
    }
    match &report.report {
        Report::TD15(report) => validate_td15(report),
        Report::TD10(report) => validate_td10(report),
        Report::SgxEnclave(report) => validate_sgx(report),
    }
}

pub fn replay_event_logs(eventlog: &[EventLog], to_event: Option<&str>) -> [[u8; 48]; 4] {
    let mut rtmrs = [[0u8; 48]; 4];
    for idx in 0..4 {
        let mut mr = [0u8; 48];

        for event in eventlog.iter() {
            if event.imr == idx {
                let digest = hex::decode(&event.digest).expect("Invalid digest hex");
                let mut hasher = Sha384::new();
                hasher.update(mr);
                hasher.update(&digest);
                mr = hasher.finalize().into();
            }
            if let Some(to_event) = to_event {
                if event.event == to_event {
                    break;
                }
            }
        }
        rtmrs[idx as usize] = mr;
    }

    rtmrs
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventLog {
    pub imr: u32,
    pub event_type: u32,
    pub digest: String,
    pub event: String,
    pub event_payload: String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum TcbStatus {
    UpToDate,
    OutOfDateConfigurationNeeded,
    OutOfDate,
    ConfigurationAndSWHardeningNeeded,
    ConfigurationNeeded,
    SWHardeningNeeded,
    Revoked,
}

impl TcbStatus {
    fn severity(&self) -> u8 {
        match self {
            Self::UpToDate => 0,
            Self::SWHardeningNeeded => 1,
            Self::ConfigurationNeeded => 2,
            Self::ConfigurationAndSWHardeningNeeded => 3,
            Self::OutOfDate => 4,
            Self::OutOfDateConfigurationNeeded => 5,
            Self::Revoked => 6,
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self, Self::Revoked)
    }
}

impl core::fmt::Display for TcbStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UpToDate => write!(f, "UpToDate"),
            Self::OutOfDateConfigurationNeeded => write!(f, "OutOfDateConfigurationNeeded"),
            Self::OutOfDate => write!(f, "OutOfDate"),
            Self::ConfigurationAndSWHardeningNeeded => write!(f, "ConfigurationAndSWHardeningNeeded"),
            Self::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            Self::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct TcbStatusWithAdvisory {
    pub status: TcbStatus,
    pub advisory_ids: Vec<String>,
}

impl TcbStatusWithAdvisory {
    pub fn new(status: TcbStatus, advisory_ids: Vec<String>) -> Self {
        Self {
            status,
            advisory_ids,
        }
    }

    pub fn merge(self, other: &TcbStatusWithAdvisory) -> Self {
        let final_status = if other.status.severity() > self.status.severity() {
            other.status
        } else {
            self.status
        };

        let mut advisory_ids = self.advisory_ids;
        for id in &other.advisory_ids {
            if !advisory_ids.contains(id) {
                advisory_ids.push(id.clone());
            }
        }

        Self {
            status: final_status,
            advisory_ids,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    #[serde(with = "serde_bytes")]
    pub ppid: Vec<u8>,
    pub qe_status: TcbStatusWithAdvisory,
    pub platform_status: TcbStatusWithAdvisory,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum Report {
    SgxEnclave(EnclaveReport),
    TD10(TDReport10),
    TD15(TDReport15),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct EnclaveReport {
    #[serde(with = "serde_bytes")]
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    #[serde(with = "serde_bytes")]
    pub reserved1: [u8; 28],
    #[serde(with = "serde_bytes")]
    pub attributes: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_enclave: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub reserved2: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub mr_signer: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub reserved3: [u8; 96],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    #[serde(with = "serde_bytes")]
    pub reserved4: [u8; 60],
    #[serde(with = "serde_bytes")]
    pub report_data: [u8; 64],
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct TDReport10 {
    #[serde(with = "serde_bytes")]
    pub tee_tcb_svn: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_seam: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_signer_seam: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub seam_attributes: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub td_attributes: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub xfam: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub mr_td: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_config_id: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_owner: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_owner_config: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr0: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr1: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr2: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr3: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub report_data: [u8; 64],
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct TDReport15 {
    pub base: TDReport10,
    #[serde(with = "serde_bytes")]
    pub tee_tcb_svn2: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_service_td: [u8; 48],
}

#[derive(Deserialize)]
pub struct AttestationResponse {
    pub success: bool,
    pub quote: Option<String>,
    pub event_log: Option<String>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub step: Option<u32>,
}
