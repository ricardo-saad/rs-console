# syntax=docker/dockerfile:1.7
FROM rust:1.85.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY api ./api
COPY auth ./auth
COPY policy ./policy
COPY server ./server
RUN cargo build --locked --release --package rs-console-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 console \
    && useradd --system --uid 10001 --gid console --home-dir /nonexistent console
COPY --from=build /src/target/release/rs-console-server /usr/local/bin/rs-console
USER 10001:10001
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/rs-console"]
CMD ["serve"]
