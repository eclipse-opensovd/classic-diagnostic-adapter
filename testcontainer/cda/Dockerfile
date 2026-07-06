# SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

ARG RUST_VERSION=1.88
ARG SOURCE_DATE_EPOCH
ARG SOURCE_GIT_SHA

# --- Stage 1: Install cargo-chef and sccache ---
FROM rust:${RUST_VERSION}-slim-trixie AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-chef and sccache
RUN cargo install cargo-chef sccache --locked

# --- Stage 2: Prepare the recipe (dependencies only) ---
FROM chef AS planner
WORKDIR /app

# Only copy cargo files, so the planner stage is cached unless dependencies change
COPY Cargo.toml Cargo.lock ./
COPY cda-main/Cargo.toml ./cda-main/Cargo.toml
COPY cda-interfaces/Cargo.toml ./cda-interfaces/Cargo.toml
COPY cda-core/Cargo.toml ./cda-core/Cargo.toml
COPY cda-comm-doip/Cargo.toml ./cda-comm-doip/Cargo.toml
COPY cda-comm-uds/Cargo.toml ./cda-comm-uds/Cargo.toml
COPY cda-database/Cargo.toml ./cda-database/Cargo.toml
COPY cda-plugin-security/Cargo.toml ./cda-plugin-security/Cargo.toml
COPY cda-plugin-runtime-update/Cargo.toml ./cda-plugin-runtime-update/Cargo.toml
COPY cda-sovd/Cargo.toml ./cda-sovd/Cargo.toml
COPY cda-tracing/Cargo.toml ./cda-tracing/Cargo.toml
COPY cda-sovd-interfaces/Cargo.toml ./cda-sovd-interfaces/Cargo.toml
COPY cda-health/Cargo.toml ./cda-health/Cargo.toml
COPY cda-extra/Cargo.toml ./cda-extra/Cargo.toml
COPY cda-storage/Cargo.toml ./cda-storage/Cargo.toml
COPY integration-tests/Cargo.toml ./integration-tests/Cargo.toml
COPY cda-build/Cargo.toml ./cda-build/Cargo.toml
COPY comm-mbedtls/mbedtls-rs/Cargo.toml ./comm-mbedtls/mbedtls-rs/Cargo.toml
COPY comm-mbedtls/mbedtls-sys/Cargo.toml ./comm-mbedtls/mbedtls-sys/Cargo.toml
COPY opensovd-axum-extra/Cargo.toml ./opensovd-axum-extra/Cargo.toml

# Generate the recipe.json which describes dependencies
RUN cargo chef prepare --recipe-path recipe.json

# --- Stage 3: Cook dependencies ---
FROM chef AS cacher
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

# Use BuildKit cache mounts for Cargo registry, Git, and sccache
# This significantly speeds up subsequent builds by reusing downloaded crates and compiled artifacts.
ENV RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

# --- Stage 4: Build the application ---
FROM chef AS builder
ARG SOURCE_DATE_EPOCH
ARG SOURCE_GIT_SHA

WORKDIR /app
# Copy pre-built dependencies from the cacher stage
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

COPY Cargo.toml Cargo.lock ./
COPY cda-main ./cda-main
COPY cda-interfaces ./cda-interfaces
COPY cda-core ./cda-core
COPY cda-comm-doip ./cda-comm-doip
COPY cda-comm-uds ./cda-comm-uds
COPY cda-database ./cda-database
COPY cda-plugin-security ./cda-plugin-security
COPY cda-plugin-runtime-update ./cda-plugin-runtime-update
COPY cda-sovd ./cda-sovd
COPY cda-tracing ./cda-tracing
COPY cda-sovd-interfaces ./cda-sovd-interfaces
COPY cda-health ./cda-health/
COPY cda-extra ./cda-extra
COPY cda-storage ./cda-storage
COPY integration-tests ./integration-tests
COPY cda-build ./cda-build
COPY comm-mbedtls ./comm-mbedtls
COPY opensovd-axum-extra ./opensovd-axum-extra

ENV RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} && \
    export SOURCE_GIT_SHA=${SOURCE_GIT_SHA} && \
        cargo build --release --bin opensovd-cda \
            --features cda-database/gen-flatbuffers,cda-database/trace-flatbuffers && \
    cp target/release/opensovd-cda /tmp/opensovd-cda

# --- Stage 5: Build patched flatc ---
FROM chef AS flatc-builder
ARG FLATBUFFERS_GIT_REV=0ba3307d110a6def7419ad1158245cdf47c6d0c5
WORKDIR /tmp

RUN git clone https://github.com/alexmohr/flatbuffers.git flatbuffers && \
    cd flatbuffers && \
    git checkout ${FLATBUFFERS_GIT_REV} && \
    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DFLATBUFFERS_BUILD_TESTS=OFF \
      -DFLATBUFFERS_BUILD_FLATLIB=OFF \
      -DFLATBUFFERS_BUILD_GRPCTEST=OFF \
      -DFLATBUFFERS_BUILD_SHAREDLIB=OFF \
      -DFLATBUFFERS_LIBCXX_WITH_CLANG=OFF && \
    cmake --build build --target flatc -- -j"$(nproc)" && \
    cp build/flatc /tmp/flatc

# --- Stage 6: Runtime base with dependencies ---
FROM debian:trixie-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    curl \
    jq \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Stage 7: Runtime stage ---
FROM runtime-base
WORKDIR /app
ENV FB_TRACE_PATH=/tmp/trace/flatbuffers-values.jsonl

# Copy the binary from /tmp
COPY --from=builder /tmp/opensovd-cda /app/opensovd-cda
COPY --from=flatc-builder /tmp/flatc /usr/local/bin/flatc
RUN mkdir -p /app/odx

COPY --chmod=755 testcontainer/cda/entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
