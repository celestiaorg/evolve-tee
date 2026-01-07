# Build stage
FROM rust:1.88 AS builder

# Install build dependencies for bindgen (requires libclang)
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22+ (required by sp1-recursion-gnark-ffi)
RUN curl -fsSL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:${PATH}"

# Install SP1 toolchain (required by ev-prover build script)
RUN curl -L https://sp1up.succinct.xyz | bash && \
    ~/.sp1/bin/sp1up --version 5.2.2
ENV PATH="/root/.sp1/bin:${PATH}"

WORKDIR /build

# Copy workspace manifest and lock file
COPY Cargo.toml Cargo.lock ./

# Copy all workspace member manifests
COPY app/Cargo.toml ./app/
COPY circuit/Cargo.toml ./circuit/
COPY light-client/Cargo.toml ./light-client/
COPY middleware/Cargo.toml ./middleware/
COPY types/Cargo.toml ./types/

# Copy build.rs for light-client (needed for sp1-build)
COPY light-client/build.rs ./light-client/

# Copy ev-batch-elf (needed by light-client include_bytes!)
COPY light-client/fixtures/ ./light-client/fixtures/

# Copy circuit source (needed by light-client build.rs to compile the circuit ELF)
COPY circuit/src ./circuit/src

# Copy types source (needed by circuit during SP1 compilation)
COPY types/src ./types/src

# Create dummy sources for app, light-client, and middleware to cache dependencies
RUN mkdir -p app/src && echo "fn main() {}" > app/src/main.rs && \
    mkdir -p light-client/src && echo "" > light-client/src/lib.rs && \
    mkdir -p middleware/src && echo "fn main() {}" > middleware/src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release -p evolve-tee && rm -rf app/src light-client/src

# Copy actual source code for remaining workspace members
COPY app/src ./app/src
COPY light-client/src ./light-client/src

# Build the actual application
RUN touch app/src/main.rs light-client/src/lib.rs && cargo build --release -p evolve-tee

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/target/release/evolve-tee .

# Copy ev-prover config files
COPY config/ /root/.ev-prover/config/

EXPOSE 8080

CMD ["./evolve-tee"]
