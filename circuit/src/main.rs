#![no_main]

sp1_zkvm::entrypoint!(main);
use types::{
    EnclaveReport, EventLog, Inputs, Report, TDReport10, TDReport15, VerifiedReport,
    replay_event_logs, validate_tcb,
};

pub fn main() {
    let inputs: Inputs = sp1_zkvm::io::read::<Inputs>();
    let verified_report = dcap_qvl::verify::verify(&inputs.quote, &inputs.collateral, inputs.now)
        .expect("Failed to verify attestation");
    let event_log: Vec<EventLog> = if !inputs.event_log.is_empty() {
        serde_json::from_slice(&inputs.event_log).unwrap()
    } else {
        panic!("Invalid event log");
    };
    if let Some(report) = verified_report.report.as_td10() {
        // Replay the event logs
        let rtmrs = replay_event_logs(&event_log, None);
        if rtmrs != [report.rt_mr0, report.rt_mr1, report.rt_mr2, report.rt_mr3] {
            panic!("RTMR mismatch");
        }
    }
    // Convert to local Report type using accessor methods
    let report = if let Some(r) = verified_report.report.as_td10() {
        Report::TD10(TDReport10 {
            tee_tcb_svn: r.tee_tcb_svn,
            mr_seam: r.mr_seam,
            mr_signer_seam: r.mr_signer_seam,
            seam_attributes: r.seam_attributes,
            td_attributes: r.td_attributes,
            xfam: r.xfam,
            mr_td: r.mr_td,
            mr_config_id: r.mr_config_id,
            mr_owner: r.mr_owner,
            mr_owner_config: r.mr_owner_config,
            rt_mr0: r.rt_mr0,
            rt_mr1: r.rt_mr1,
            rt_mr2: r.rt_mr2,
            rt_mr3: r.rt_mr3,
            report_data: r.report_data,
        })
    } else if let Some(r) = verified_report.report.as_td15() {
        Report::TD15(TDReport15 {
            base: TDReport10 {
                tee_tcb_svn: r.base.tee_tcb_svn,
                mr_seam: r.base.mr_seam,
                mr_signer_seam: r.base.mr_signer_seam,
                seam_attributes: r.base.seam_attributes,
                td_attributes: r.base.td_attributes,
                xfam: r.base.xfam,
                mr_td: r.base.mr_td,
                mr_config_id: r.base.mr_config_id,
                mr_owner: r.base.mr_owner,
                mr_owner_config: r.base.mr_owner_config,
                rt_mr0: r.base.rt_mr0,
                rt_mr1: r.base.rt_mr1,
                rt_mr2: r.base.rt_mr2,
                rt_mr3: r.base.rt_mr3,
                report_data: r.base.report_data,
            },
            tee_tcb_svn2: r.tee_tcb_svn2,
            mr_service_td: r.mr_service_td,
        })
    } else if let Some(r) = verified_report.report.as_sgx() {
        Report::SgxEnclave(EnclaveReport {
            cpu_svn: r.cpu_svn,
            misc_select: r.misc_select,
            reserved1: r.reserved1,
            attributes: r.attributes,
            mr_enclave: r.mr_enclave,
            reserved2: r.reserved2,
            mr_signer: r.mr_signer,
            reserved3: r.reserved3,
            isv_prod_id: r.isv_prod_id,
            isv_svn: r.isv_svn,
            reserved4: r.reserved4,
            report_data: r.report_data,
        })
    } else {
        panic!("Unknown report type");
    };

    let verifed_report_alias = VerifiedReport {
        status: verified_report.status.clone(),
        advisory_ids: verified_report.advisory_ids.clone(),
        report,
        ppid: verified_report.ppid.clone(),
    };
    validate_tcb(&verifed_report_alias);
    sp1_zkvm::io::commit_slice(Vec::new().as_slice());
}
