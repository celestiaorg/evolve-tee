# Evolve Light Client using ZKPs of TEE Attestations

> **⚠️ WARNING: This code has not been audited and is a work in progress. Do not use in production.**

This project consists of two components that enable TEE attestations over Evolve State Roots:

`app`: The Phala application that attests to the replay of the executor inputs for a range of blocks

`circuit`: The SP1 program that verifies the attestation and outputs  previous_state || new_state

`light-client`: Block verification logic that depends largely on `celestia-zkevm`

## Prerequisites
There exists a docker image in [celestia-zkevm](https://github.com/celestiaorg/celestia-zkevm/blob/main/docker-compose.yml) that includes everything (ev-node, ev-reth, celestia-app, zkism deployment).

```
git clone git@github.com:celestiaorg/celestia-zkevm
cd celestia-zkevm
make start && make deploy-ism && make update-ism
```

## Publish the Phala app's docker image
```
phala docker build

phala docker push
```

## Deploy the Phala TEE instance
```
phala deploy --interactive
```

This will output a URL to the Phala dashboard for the newly created instance.
Navigate to `dashboard=>Network` and find the RPC URL used to request attestations and set it as `TEE_APP_URL`. Example: `https://e3ef58deb2acad4bd5dcc36b39e079198104745f-8080.dstack-pha-prod5.phala.network/attestation`.

## Performance

### Current Bottlenecks
The main performance bottleneck is **sequential querying of Celestia blocks and blobs**. Each block must be fetched individually before its associated blob data can be retrieved, creating a serial dependency chain.

### Scaling Characteristics
- **Scales well**: Block ranges containing many transactions per block
- **Room for improvement**: Large block ranges with sparse transactions

The current implementation performs optimally when processing blocks with high transaction density, but can be optimized further for scenarios involving many blocks with few transactions each.

## TODO

### Circuit Constraints
For development purposes, the circuit does not yet fully constrain the execution environment. The following TEE measurements need to be asserted in the circuit:

- `os_image_hash` - Hash of the operating system image
- `mr_system` - Measurement register for system components
- `mr_aggregated` - Aggregated measurement register
- `mrtd` - Measurement register for TDX domains
- `rtmr0-3` - Runtime Measurement Registers (0 through 3)
- `compose_hash` - Hash of the compose configuration

These constraints will ensure that proofs can only be generated from authorized TEE environments with verified configurations.
