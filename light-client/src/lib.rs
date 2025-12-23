use anyhow::{Result, anyhow};
use ev_zkevm_types::programs::block::{BlockExecInput, BlockRangeExecOutput, BlockVerifier};
use tendermint_light_client_verifier::types::LightBlock;

pub async fn verify_blocks(
    inputs: Vec<BlockExecInput>,
    trusted_light_block: LightBlock,
    new_light_block: LightBlock,
) -> Result<BlockRangeExecOutput> {
    let verifier = BlockVerifier {};
    Ok(verifier
        .verify_range(inputs, trusted_light_block, new_light_block)
        .map_err(|e| anyhow!("{e}"))?)
}
