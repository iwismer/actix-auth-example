FROM clux/muslrust:stable as build
# Install build deps package
RUN cargo install cargo-bdeps
# Set workdir to root
WORKDIR /
# Create sample project
RUN USER=root cargo new --bin auth-example
# Make it the workdir
WORKDIR /auth-example
# Copy over toml files
COPY Cargo.toml Cargo.lock ./
# Build the dependencies
RUN cargo-bdeps --release
# Build will be cached up to here unless Cargo.toml is updated

# Copy over all project files
COPY src src
COPY templates templates
# Build the whole thing
RUN cargo build --release --bin auth-example
# Copy over the static content
COPY static static
COPY .well-known .well-known
# Copy over to other container
RUN mkdir -p move/auth-example
RUN cp -r static move/
RUN cp -r .well-known move/
RUN cp -r templates move/auth-example/
RUN cp /auth-example/target/x86_64-unknown-linux-musl/release/auth-example move/auth-example/
RUN strip move/auth-example/auth-example
RUN ls move/

FROM gcr.io/distroless/static
COPY --from=build /auth-example/move /
EXPOSE 8080
CMD ["/auth-example/auth-example"]
