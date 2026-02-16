# Evolve Light Client using ZKPs of TEE Attestations

> **⚠️ WARNING: This code has not been audited and is a work in progress. Do not use in production.**

This project consists of two components that enable TEE attestations over Evolve State Roots:

`app`: A minimal Phala TEE application that performs native block verification on provided inputs and generates attestations

`circuit`: The SP1 program that verifies the attestation and outputs previous_state || new_state

## Architecture

The TEE app receives all necessary data via a POST request to `/attestation`:
- **Block inputs**: Hex-encoded bincode-serialized `BlockExecInput` objects
- **Light blocks**: Hex-encoded CBOR-serialized Tendermint light blocks for verification

This design makes the TEE environment **self-contained** with no external dependencies - all data fetching is performed by the prover before sending the request.

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
Navigate to `dashboard=>Network` and find the RPC URL and set it as `TEE_APP_URL`. Example: `https://e3ef58deb2acad4bd5dcc36b39e079198104745f-8080.dstack-pha-prod5.phala.network`.

## API Endpoints

### POST /attestation
Performs block verification and generates a TEE attestation.

**Request Body:**
```json
{
  "block_inputs": ["<hex-encoded-bincode-BlockExecInput>", ...],
  "trusted_light_block_raw": "<hex-encoded-cbor-LightBlock>",
  "new_light_block_raw": "<hex-encoded-cbor-LightBlock>"
}
```

**Response:**
```json
{
  "success": true,
  "quote": "<hex-encoded-quote>",
  "event_log": "<event-log-string>",
  "output": "<hex-encoded-BlockRangeExecOutput>",
  "timing": {
    "deserialize_seconds": 0.05,
    "verify_blocks_seconds": 1.23
  }
}
```

### GET /health
Returns health status of the TEE app.

### GET /info
Returns TEE environment information.

### GET /quote
Returns a simple TEE quote with zero report data (for testing).

## Performance

### Architecture Benefits
The TEE app is **lightweight and fast** since:
- No external RPC calls or network I/O within the TEE
- Direct native execution without zkVM overhead
- All data is pre-fetched and validated by the prover

### Data Flow
1. **Prover** (outside TEE): Fetches blocks, blobs, and light blocks from Celestia/EVM nodes
2. **TEE App**: Receives serialized data, performs verification, generates attestation
3. **Circuit**: Verifies the TEE attestation in SP1

This separation allows the expensive data fetching to occur outside the TEE while keeping the attestation generation secure and efficient.

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
