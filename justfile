set windows-shell := ["pwsh", "-NoProfile", "-Command"]

[private]
default:
    @just --list

# Build the host and stage every plugin package (library and schema.json); pass --release for shipping libraries.
build *args:
    bun scripts/build.mjs {{ args }}

# Test all workspace members using the committed lockfile.
test *args:
    cargo test --locked --workspace {{ args }}

# Lint the SDK, process host and plugins.
clippy:
    cargo clippy --locked --workspace --all-targets

# Format all workspace members.
fmt:
    cargo fmt --all
