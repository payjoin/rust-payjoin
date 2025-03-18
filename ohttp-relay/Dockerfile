# Stage 1: Building the binary
FROM nixos/nix:2.20.5 AS builder

# Set ohttp-relay branch or tag to build from
ARG BRANCH=v0.0.9

# Copy our source and setup our working directory
COPY . /tmp/build
WORKDIR /tmp/build

# Build our Nix environment
RUN nix \
    --extra-experimental-features "nix-command flakes" \
    --option filter-syscalls false \
    build

# Copy the Nix store closure into a directory. The Nix store closure is the
# entire set of Nix store values that we need for our build.
RUN mkdir /tmp/nix-store-closure \
    && cp -R $(nix-store -qR result/) /tmp/nix-store-closure

# Stage 2: running ohttp-relay
# Final image is based on scratch. We copy a bunch of Nix dependencies
# but they're fully self-contained so we don't need Nix anymore.
FROM scratch AS final

WORKDIR /ohttp-relay

# Copy necessary files from builder stage
COPY --from=builder /tmp/nix-store-closure /nix/store
COPY --from=builder /tmp/build/result/bin/ohttp-relay /bin/ohttp-relay

# Run ohttp-relay at start
CMD ["/bin/ohttp-relay"]
