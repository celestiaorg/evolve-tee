# Build stage
FROM rust:1.88 AS builder

# Install build dependencies for bindgen (requires libclang)
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifest and lock file
COPY Cargo.toml Cargo.lock ./

# Copy app manifest
COPY app/Cargo.toml ./app/

# Create a dummy main.rs to cache dependencies
RUN mkdir -p app/src && echo "fn main() {}" > app/src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf app/src

# Copy actual source code
COPY app/src ./app/src

# Build the actual application
RUN touch app/src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/target/release/evolve-tee .

EXPOSE 8080

CMD ["./evolve-tee"]
