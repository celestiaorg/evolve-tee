# Evolve-TEE Project Context

## Project Overview
Zero-Knowledge Proofs (ZKPs) of TEE Attestations for blockchain state verification. Verifies block execution using TEE attestations from Trusted Execution Environments (SGX/TDX) and provides an attestation over verified evolve state that can be wrapped in a zk circuit.

**Tech Stack:** Rust, SP1 ZK proving, TEE (Phala/DStack), Celestia DA, EVM execution

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ TEE Server (app:8080)                                                   │
│  - /attestation: Generate state root attestations                       │
│  - /quote: TEE quote generation                                         │
│  - /health, /info                                                       │
└─────────────────┬───────────────────────────────────────────────────────┘
                  │ 1 HTTP request
                  ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ Middleware (middleware:9091)                                            │
│  - /query_block_inputs: Fetch & prepare block inputs                   │
│  - Batch prefetch Celestia data (headers, blobs, proofs)               │
│  - Parallel executor input generation (MAX_CONCURRENCY=100)            │
└─────────────────┬───────────────────────────────────────────────────────┘
                  │ Many RPC calls
                  ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ External Services                                                       │
│  - Celestia RPC/gRPC (DA layer)                                        │
│  - Tendermint RPC (consensus)                                          │
│  - RETH RPC/WS (EVM execution)                                         │
│  - EV-Node RPC (sequencer)                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### `/app` - TEE Application
**Entry:** `app/src/main.rs`
**Purpose:** HTTP API that generates TEE attestations for block verification
**Port:** 8080

Main workflow:
1. Connect to Celestia ISM (gRPC) and query trusted state
2. Call middleware to fetch block inputs
3. Perform native block verification via light-client
4. Return attestation with timing metrics

### `/middleware` - Block Input Preparation Service
**Entry:** `middleware/src/bin/middleware.rs`
**Purpose:** Handles expensive network operations outside TEE
**Port:** 9091

Optimizations:
- Batch header fetching: 1 request instead of N (reduces 3N → 2N+1 RPC calls)
- Parallel blob/proof fetching with controlled concurrency
- Returns pre-built `BlockExecInput` structures

### `/light-client` - Block Verification Logic
**Entry:** `light-client/src/lib.rs`
**Purpose:** Core verification, state computation, and data fetching logic

Key functions:
- `prefetch_celestia_data_batch()` - Fetches Celestia data for height range
- `build_block_input_from_prefetched()` - Constructs block execution inputs
- `verify_blocks()` - Native block verification (replaces SP1 for TEE)
- `fetch_block_inputs_from_middleware()` - HTTP client for middleware
- `get_light_block()` - Tendermint light client data

### `/circuit` - SP1 ZK Verification Program
**Entry:** `circuit/src/main.rs`
**Purpose:** Verifies TEE attestations and generates ZK proofs

Process:
1. Reads inputs (quote, event log, report data, output, collateral)
2. Verifies TEE quote using DCAP-QVL
3. Validates event logs and replays RTMRs (Runtime Measurements)
4. Validates TCB (prevents debug mode, validates sealing keys)
5. Verifies output hash matches report_data
6. Commits proof to public outputs

Supports: SGX Enclave, Intel TDX 1.0/1.5 reports

### `/types` - Shared Data Structures
**Entry:** `types/src/lib.rs`
**Purpose:** TEE report types, event logs, validation utilities

## Key Environment Variables

### Required RPC Endpoints
```bash
RETH_RPC_URL=http://...              # EVM execution RPC (HTTP)
RETH_WS_URL=ws://...                 # EVM execution RPC (WebSocket)
CELESTIA_RPC_URL=http://...          # Celestia DA RPC
TENDERMINT_RPC_URL=http://...        # Tendermint consensus RPC
EV_NODE_URL=http://...               # EV-Node (sequencer) RPC
CELESTIA_GRPC_ENDPOINT=grpc://...    # Celestia gRPC endpoint
```

### Application Config
```bash
MIDDLEWARE_ENDPOINT=http://...       # Middleware service URL
TEE_APP_URL=https://...              # TEE app endpoint (Phala deployment)
PUBKEY=...                           # Public key for verification
```

### Celestia/Hyperlane
```bash
CELESTIA_ISM_ID=...                  # Interchain Security Module ID
CELESTIA_NAMESPACE=...               # Data namespace
CELESTIA_PRIVATE_KEY=...             # Private key for transactions
MAILBOX_ADDRESS=0x...                # EVM Hyperlane Mailbox contract
CELESTIA_MAILBOX_ADDRESS=...         # Celestia Mailbox ID
MERKLE_TREE_ADDRESS=0x...            # EVM Merkle Tree contract
```

### Proving (SP1)
```bash
SP1_PROVER=mock|cpu|cuda|network    # Proof generation mode
NETWORK_PRIVATE_KEY=...              # Succinct Prover Network auth
```

### Keys
```bash
PRIVATE_KEY=0x...                    # EVM transaction signing key
```

## Common Tasks

### Build & Run TEE App
```bash
cargo run --bin evolve-tee
```

### Build & Run Middleware
```bash
cargo run --bin middleware
```

### Run Tests
```bash
cargo test --workspace
```

### Build Circuit
```bash
cd light-client
cargo build --release
```

### Deploy to Phala
```bash
phala docker build
phala docker push
phala deploy --interactive
```

## Main Workflows

### TEE Attestation Flow
```
GET /attestation
  ↓
1. Query ISM for trusted state (height, state_root, celestia_height)
2. Get Celestia head (limit MAX_BLOCKS=10000)
3. Call middleware: fetch_block_inputs(from, to, trusted_height, trusted_root)
4. Fetch Tendermint light blocks (trusted & new height)
5. Run verify_blocks() → BlockRangeExecOutput
6. Generate TEE quote with output hash
7. Return attestation + timing metrics
```

### Middleware Block Input Flow
```
GET /query_block_inputs?from_height=X&to_height=Y&trusted_height=Z&trusted_root=HASH
  ↓
1. Batch fetch headers: header_get_range_by_height()
2. Parallel fetch blobs: blob_get_all() (100 concurrent)
3. Parallel fetch proofs: share_get_namespace_data()
4. Extract executor input heights from blobs
5. Parallel fetch EVM state for each height
6. Build BlockExecInput structures
7. Return serialized inputs + timing
```

## Performance Characteristics

### Timing Metrics Tracked
- **prefetch_seconds**: Time to fetch Celestia data (headers, blobs, proofs)
- **host_executor_seconds**: Cumulative time in host_executor.execute() across all blocks
- **executor_inputs_seconds**: Time for build_block_input_from_prefetched loop
- **verify_blocks_seconds**: Time for native block verification in TEE

### Optimization Notes
- Middleware reduces TEE network calls from O(n) to O(1) for n blocks
- Batch header fetching: 1 request vs N individual requests
- Controlled concurrency: MAX_CONCURRENCY=100 parallel requests
- Sequential state updates maintain trusted state consistency

## Dependencies

### Core Technologies
- **sp1-sdk** (5.2.2) - ZK proving system
- **alloy** (1.0.32) - Ethereum library ecosystem
- **reth** (1.5.0) - Execution client components
- **rsp** - Remote State Proof executor (Succinct Labs)
- **celestia-rpc/types** (0.13.0/0.15.0) - Celestia client
- **dstack-sdk/verifier** - TEE operations & verification
- **dcap-qvl** - Intel DCAP Quote Verification
- **tendermint-rpc/light-client** (0.40.1) - Tendermint consensus

### Build System
- Workspace: `app`, `circuit`, `light-client`, `middleware`, `types`
- SP1 patches for crypto precompiles (sha2, sha3, k256, p256, curve25519)
- Build script compiles SP1 circuit at `light-client/build.rs`

## File Structure
```
evolve-tee/
├── app/src/main.rs              # TEE HTTP API (8080)
├── middleware/
│   ├── src/lib.rs               # Core middleware logic
│   └── src/bin/middleware.rs    # HTTP server (9091)
├── light-client/
│   ├── src/lib.rs               # Verification & data fetching
│   ├── build.rs                 # SP1 circuit build
│   └── fixtures/                # Compiled ELF binaries
├── circuit/src/main.rs          # SP1 TEE verification program
├── types/src/lib.rs             # Shared TEE report types
├── config/
│   ├── config.yaml              # RPC configuration
│   └── genesis.json             # Genesis state
├── Cargo.toml                   # Workspace config
└── docker-compose.yml           # Service orchestration
```

## Development Notes

### Prerequisites
Requires celestia-zkevm stack:
```bash
git clone git@github.com:celestiaorg/celestia-zkevm
cd celestia-zkevm
make start && make deploy-ism && make update-ism
```

### Configuration Files
- `.env` / `.env.example` - Environment variables
- `config/config.yaml` - RPC endpoints and Hyperlane config
- `config/genesis.json` - Genesis block state

### Debugging
- Console logs include timing breakdowns for each step
- JSON responses include detailed timing in `timing` field
- Health endpoints: `/health` (app), `/health` (middleware)

## Code Patterns

### Error Handling
- Uses `anyhow::Result` throughout
- Returns JSON errors with `step` field indicating failure point
- Middleware returns `success: false` with error message

### Parallelization
- `futures::stream` with `.buffered(MAX_CONCURRENCY)` for controlled parallelism
- `.try_collect()` for collecting results
- Sequential processing where state consistency required

### Timing Instrumentation
```rust
let start = std::time::Instant::now();
// ... operation ...
let duration = start.elapsed();
println!("Operation took {:.2}s", duration.as_secs_f64());
```

### State Management
```rust
// Sequential trusted state updates
for prefetched_data in prefetched {
    let (input, executor_time) = build_block_input_from_prefetched(
        chain_context.clone(),
        prefetched_data,
        &mut trusted_height,  // mutable state
        &mut trusted_root,    // mutable state
    ).await?;
}
```
