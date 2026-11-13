# sealantd Agent Guidelines

Rules and skills shared by every Sealant repo, including Linear, PRs, verification and model choice,
live in the home repo, cloned beside this one at `../agent-home`. Start sessions there when work
spans repos.

## Linux only

sealantd targets Linux. On a Mac, run every `cargo` command except `cargo fmt` in a Linux container,
the way `scripts/linux-test.sh` does:

```sh
docker run --rm -v "$PWD":/src -w /src \
  -v sealantd-cargo-registry:/usr/local/cargo/registry \
  -v sealantd-linux-target:/src/target \
  rust:1.100.0-slim <command>
```

## Checks before a PR

CI (`.github/workflows/ci.yml`) runs these on x64 and arm64. Run them before pushing and see them
pass:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace --no-fail-fast   # or `cargo test --workspace` without nextest
cargo test --workspace --doc
```

When the change touches `packages/`, also run `pnpm install --frozen-lockfile`, `pnpm -r build` and
`pnpm -r test`. The package tests start a real daemon, so build it first
(`cargo build --locked -p sealantd`), on Linux.

CI also runs root tests (`scripts/ci-root-tests.sh`) that add users and install packages. Leave
those to CI unless the change touches ownership, users or boot privileges, and then run them only in
a throwaway container.

When a `.proto` file changes, run `pnpm exec buf generate` and commit the regenerated TypeScript in
`packages/runtime-protocol/src/gen`. CI doesn't check that it is up to date.

A change users of the daemon or the packages would notice needs a changeset (`pnpm changeset`), daemon
fixes included. See `.changeset/README.md`.

## Verifying a change

Tests passing is not verification. To see a change working in a real daemon, use the `verify` skill
in `.agents/skills/verify/`.
