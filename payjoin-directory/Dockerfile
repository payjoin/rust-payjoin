# Use the official Rust image as the builder
FROM --platform=linux/amd64 rust:1.81-slim as builder

WORKDIR /usr/src/payjoin-directory

# Install cross-compilation dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    musl-tools \
    musl-dev \
    pkg-config \
    gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

# Set the linker
ENV CC_x86_64_unknown_linux_musl=musl-gcc
ENV AR_x86_64_unknown_linux_musl=ar

# Add the x86_64-unknown-linux-musl target
RUN rustup target add x86_64-unknown-linux-musl

# Copy the workspace manifest and source code
COPY . .

# Build the binary
RUN cargo build --bin payjoin-directory --release --target x86_64-unknown-linux-musl

# Create final minimal image
FROM --platform=linux/amd64 alpine:latest

# Copy the binary from builder
COPY --from=builder /usr/src/payjoin-directory/target/x86_64-unknown-linux-musl/release/payjoin-directory ./

# Run the binary
ENTRYPOINT ["./payjoin-directory"]