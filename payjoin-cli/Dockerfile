# x86_64-unknown-linux-musl

## Initial build Stage
FROM rustlang/rust:nightly

WORKDIR /usr/src/payjoin-cli
COPY Cargo.toml Cargo.lock ./
COPY payjoin/Cargo.toml ./payjoin/
COPY payjoin/src ./payjoin/src/
COPY payjoin-cli/Cargo.toml ./payjoin-cli/
COPY payjoin-cli/src ./payjoin-cli/src/

# Install the required dependencies to build for `musl` static linking
RUN apt-get update && apt-get install -y musl-tools musl-dev
# Add our x86 target to rust, then compile and install
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --bin=payjoin-cli --target x86_64-unknown-linux-musl --features=native-certs

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=0 /usr/src/payjoin-cli/target/x86_64-unknown-linux-musl/release/payjoin-cli ./
# Run
ENTRYPOINT ["./payjoin-cli"]