## Summary
Stacked on #5551.

- New leaf crate `guard-command-catalog-data` owns the packaged catalog generation: canonical-source reads, trust-map projection, host-compiler `compile_catalog_with_mcp`, zstd-19 compression, and round-trip validation — moved verbatim from `guard-command/build.rs`
- `guard-command` consumes the packaged bytes/digests as constants (`include_bytes!`/`env!` reads replaced in `native_command_program.rs`, `native_command_catalog.rs`, `source_cli.rs`, and test files); its build script is now emit-only for the shared implementation identity
- `guard-command` build-dependencies drop `guard-command-build`, `zstd`, `ruzstd`, `hex` — the host compiler only feeds the data leaf now
- The crate is added to `command_source_inputs.v1.json` and falls into the `test-core` partition via the workspace member list

#### Motivation
A `guard-command` source edit previously reran the whole catalog pipeline (source compile, trust map, zstd-19) inside its own build script. Now catalog artifacts regenerate only when catalog inputs or the compiler identity change; crate-local edits leave the data leaf untouched. A new workspace member also causes a one-time `rust-cache` rebuild on main.

#### Test plan
- [x] `catalog-data/build.rs` compiles against the real host rlib and executes the full generation path (identity assert verified working)
- [x] `src/lib.rs` compiles against the real packaged artifacts
- [x] Digest parity: `emit()` == Python mirror == `6018bb49…` on this tree
- [x] Contract tests: manifest closure accepts the new member; new cycle-freedom test (`guard-command-build` has no path to facade or data leaf); windows-CI input collector and regen-trigger coverage retargeted
- [ ] CI: full `cargo build`, packaged-artifact verification, and trust-linkage gates

Generated with [Devin](https://devin.ai)
