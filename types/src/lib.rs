use core::panic;

use dcap_qvl::QuoteCollateralV3;
//use dcap_qvl::QuoteCollateralV3;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

/// Custom serde module for human-readable hex encoding of byte arrays.
/// For human-readable formats (JSON), encodes as hex string.
/// For binary formats, uses serde_bytes for efficiency.
pub mod serde_human_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes.as_ref()))
        } else {
            serde_bytes::serialize(bytes.as_ref(), serializer)
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: TryFrom<Vec<u8>>,
        <T as TryFrom<Vec<u8>>>::Error: core::fmt::Debug,
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(Error::custom)?
        } else {
            serde_bytes::deserialize(deserializer)?
        };
        T::try_from(bytes).map_err(|e| Error::custom(format!("{:?}", e)))
    }
}

/// Custom serde module for human-readable hex encoding of fixed-size byte arrays.
/// Handles empty strings by treating them as all-zero arrays (for dstack-qvl compatibility).
pub mod serde_human_bytes_array {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serde_bytes::serialize(bytes.as_ref(), serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            // Handle empty strings as all-zero arrays (dstack-qvl compatibility)
            if s.is_empty() {
                return Ok([0u8; 48]);
            }
            let bytes = hex::decode(&s).map_err(Error::custom)?;
            if bytes.len() != 48 {
                return Err(Error::custom(format!("Expected 48 bytes, got {}", bytes.len())));
            }
            let mut array = [0u8; 48];
            array.copy_from_slice(&bytes);
            Ok(array)
        } else {
            let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
            if bytes.len() != 48 {
                return Err(Error::custom(format!("Expected 48 bytes, got {}", bytes.len())));
            }
            let mut array = [0u8; 48];
            array.copy_from_slice(&bytes);
            Ok(array)
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Inputs {
    pub quote: Vec<u8>,
    pub event_log: Vec<u8>,
    pub report_data: Vec<u8>,
    pub output: Vec<u8>,
    pub collateral: QuoteCollateralV3,
    pub now: u64,
}

/// Validate the TCB attributes
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
            event.validate();
            if event.imr == idx {
                // For IMR 3, compute digest from event data if digest is empty (all-zero)
                // For other IMRs, skip events with all-zero digests
                let digest = if event.digest == [0u8; 48] && idx == 3 {
                    event_digest(event.event_type, &event.event, &event.event_payload)
                } else if event.digest != [0u8; 48] {
                    event.digest
                } else {
                    // Skip events with all-zero digests for IMR 0-2
                    continue;
                };

                let mut hasher = Sha384::new();
                hasher.update(mr);
                hasher.update(digest);
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
    /// IMR index, starts from 0
    pub imr: u32,
    /// Event type
    pub event_type: u32,
    /// Digest
    #[serde(with = "serde_human_bytes_array")]
    pub digest: [u8; 48],
    /// Event name
    pub event: String,
    /// Event payload
    #[serde(with = "serde_human_bytes")]
    pub event_payload: Vec<u8>,
}

impl EventLog {
    pub fn new(imr: u32, event_type: u32, event: String, event_payload: Vec<u8>) -> Self {
        let digest = event_digest(event_type, &event, &event_payload);
        Self {
            imr,
            event_type,
            digest,
            event,
            event_payload,
        }
    }

    pub fn new_str(imr: u32, event_type: u32, event: &str, event_payload: &str) -> Self {
        Self::new(
            imr,
            event_type,
            event.to_string(),
            event_payload.as_bytes().to_vec(),
        )
    }

    pub fn validate(&self) {
        if self.imr != 3 {
            // TODO: validate other imrs
            return;
        }
        // Skip validation for all-zero digests (originally empty strings from dstack-qvl)
        // These represent events where digest validation is not applicable
        if self.digest == [0u8; 48] {
            return;
        }
        let digest = event_digest(self.event_type, &self.event, &self.event_payload);
        if digest != self.digest {
            panic!("invalid digest");
        }
    }
}

fn event_digest(ty: u32, event: &str, payload: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    let mut hasher = sha2::Sha384::new();
    hasher.update(ty.to_ne_bytes());
    hasher.update(b":");
    hasher.update(event.as_bytes());
    hasher.update(b":");
    hasher.update(payload);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    #[serde(with = "serde_bytes")]
    pub ppid: Vec<u8>,
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

/// Response from the TEE app's `/attestation` endpoint.
#[derive(Deserialize)]
pub struct AttestationResponse {
    /// Whether the attestation request was successful.
    pub success: bool,
    /// Hex-encoded SGX/TDX quote bytes.
    pub quote: Option<String>,
    /// Event log data for attestation verification.
    pub event_log: Option<String>,
    /// Hex-encoded output data committed to in the attestation.
    pub output: Option<String>,
    /// Error message if the attestation failed.
    pub error: Option<String>,
    /// Step at which the attestation failed (if applicable).
    pub step: Option<u32>,
}
