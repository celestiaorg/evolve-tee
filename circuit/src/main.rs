#![no_main]

sp1_zkvm::entrypoint!(main);
use dstack_verifier::Attestation;
use types::Inputs;

pub fn main() {
    let inputs: Inputs = sp1_zkvm::io::read::<Inputs>();
    let attestation =
        Attestation::new(inputs.quote, inputs.event_log).expect("Failed to create attestation");
    let verified_attestation = attestation
        .clone()
        .verify_with_collateral(
            &inputs.report_data.try_into().unwrap(),
            inputs.collateral,
            inputs.now,
        )
        .expect("Failed to verify collateral");

    // Decode app info
    match verified_attestation.decode_app_info(false) {
        Ok(info) => {}
        Err(e) => {
            panic!("Failed to decode app info: {}", e);
        }
    };
    sp1_zkvm::io::commit_slice(Vec::new().as_slice());
}
