# Middleware Service

This middleware service provides an efficient HTTP endpoint for querying block inputs in bulk. It's designed to reduce network overhead for TEE servers by consolidating multiple blockchain queries into a single HTTP request.

## Overview

When running in a TEE environment, network calls are expensive. This middleware acts as an intermediary service that handles all the expensive network operations (Celestia RPC calls, EVM RPC calls, etc.) and returns pre-built `BlockExecInput` data structures in a single response.

## Architecture

```
TEE Server (app)  --[1 HTTP request]-->  Middleware  --[many RPC calls]-->  Celestia/EVM nodes
```

Instead of the TEE making hundreds of network calls to:
- Fetch Celestia headers
- Fetch Celestia blobs
- Fetch namespace proofs
- Fetch EVM block data
- Build executor inputs

The middleware does all of this and returns a single response with all `Vec<BlockExecInput>`.

## Running the Middleware

1. Set up your environment variables in `.env`:
```bash
CELESTIA_RPC_URL=<celestia_rpc_endpoint>
EV_NODE_URL=<evnode_endpoint>
RETH_RPC_URL=<reth_rpc_endpoint>
RETH_WS_URL=<reth_ws_endpoint>
CELESTIA_GRPC_ENDPOINT=<celestia_grpc_endpoint>
PUBKEY=<your_public_key>
```

2. Run the middleware:
```bash
cargo run --bin middleware
```

The service will start on `http://0.0.0.0:9091` and will be externally accessible.

## API Endpoints

### GET /query_block_inputs

Query block inputs for a range of Celestia heights.

**Query Parameters:**
- `from_height` (u64): Starting Celestia height (inclusive)
- `to_height` (u64): Ending Celestia height (inclusive)
- `trusted_height` (u64): Trusted EVM block height
- `trusted_root` (string): Trusted EVM state root as hex string (without 0x prefix)

**Example:**
```bash
curl "http://178.199.12.26:9091/query_block_inputs?from_height=100&to_height=105&trusted_height=50&trusted_root=abcd...1234"
```

**Response:**
```json
{
  "success": true,
  "block_inputs": [
    "hex_encoded_block_input_1",
    "hex_encoded_block_input_2",
    ...
  ],
  "error": null
}
```

Each block input is serialized using `bincode` and hex-encoded.

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "celestia_rpc_url": "...",
  "evnode_rpc_url": "..."
}
```

## Integration with TEE App

The TEE app in [app/src/main.rs](../app/src/main.rs) uses the middleware by:

1. Setting the `MIDDLEWARE_ENDPOINT` environment variable (e.g., `http://178.199.12.26:9091`)
2. Calling `fetch_block_inputs_from_middleware()` with the required parameters
3. Receiving all block inputs in a single response
4. Proceeding with verification

This reduces network calls from the TEE from O(n) to O(1) where n is the number of blocks.

## Performance

For 100 blocks, this reduces TEE network calls from:
- ~300+ individual RPC calls (headers, blobs, proofs, executor inputs)

To:
- 1 HTTP request to the middleware

This is critical in TEE environments where network I/O is significantly more expensive than regular compute.
