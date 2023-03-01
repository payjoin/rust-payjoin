# x86_64-unknown-linux-musl

## Initial build Stage
FROM rustlang/rust:nightly

WORKDIR /usr/src/payjoin-client
COPY Cargo.toml Cargo.lock ./
COPY payjoin/Cargo.toml ./payjoin/
COPY payjoin/src ./payjoin/src/
COPY payjoin-client/Cargo.toml ./payjoin-client/
COPY payjoin-client/src ./payjoin-client/src/

# Install the required dependencies to build for `musl` static linking
RUN apt-get update && apt-get install -y musl-tools musl-dev libssl-dev
# Add our x86 target to rust, then compile and install
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --bin=payjoin-client --target x86_64-unknown-linux-musl --features=native-tls-vendored

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=0 /usr/src/payjoin-client/target/x86_64-unknown-linux-musl/release/payjoin-client ./
# Run
ENTRYPOINT ["./payjoin-client"]