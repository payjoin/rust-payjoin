# x86_64-unknown-linux-musl

## Initial build Stage 
FROM rustlang/rust:nightly

WORKDIR /usr/src/payjoin-relay
COPY Cargo.toml Cargo.lock ./
COPY nnpsk0/Cargo.toml ./nnpsk0/
COPY nnpsk0/src ./nnpsk0/src/
COPY payjoin/Cargo.toml ./payjoin/
COPY payjoin/src ./payjoin/src/
COPY payjoin-client/Cargo.toml ./payjoin-client/
COPY payjoin-client/src ./payjoin-client/src/
COPY payjoin-relay/Cargo.toml ./payjoin-relay/
COPY payjoin-relay/src ./payjoin-relay/src/

# Install the required dependencies to build for `musl` static linking
RUN apt-get update && apt-get install -y musl-tools musl-dev libssl-dev
# Add our x86 target to rust, then compile and install
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --bin=payjoin-relay --target x86_64-unknown-linux-musl

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=0 /usr/src/payjoin-relay/target/x86_64-unknown-linux-musl/release/payjoin-relay ./
# Run
ENTRYPOINT ["./payjoin-relay"]

