# goblin-sigscan

`goblin-sigscan` provides pelite-style pattern parsing and scanner behavior over
goblin-backed PE/ELF/Mach binaries.

## Workspace crates

- `crates/goblin-sigscan-pattern`: pattern parser and atom model
- `crates/goblin-sigscan`: scanner/runtime API and format wrappers
- `crates/goblin-sigscan-macros`: `pattern!` compile-time parsing macro
- `crates/goblin-sigscan-cli`: small CLI for pelite-style signature scanning

## Quick start

```rust
use goblin_sigscan::pattern;

let atoms = pattern::parse("48 8B ? ? ? ? 48 89")?;
let save_slots = pattern::save_len(&atoms);
assert!(save_slots >= 1);
# Ok::<(), goblin_sigscan::pattern::ParsePatError>(())
```

Before scanning, ensure the `save` buffer has enough capacity for at least
`pattern::save_len(&atoms)` elements (or `PreparedPattern::required_slots()`).
Slot `0` always holds the match base address.

For syntax onboarding, see the public docs on `goblin_sigscan::pattern` and
`goblin_sigscan_pattern::parse`.

Docs.rs navigation shortcuts:

- crate tutorial: <https://docs.rs/goblin-sigscan/latest/goblin_sigscan/>
- pattern module: <https://docs.rs/goblin-sigscan/latest/goblin_sigscan/pattern/>
- parser crate: <https://docs.rs/goblin-sigscan-pattern/latest/goblin_sigscan_pattern/>

## Benchmarks

See `scripts/README.md` for benchmark workflows, A/B comparisons, and guidance
for reducing run-to-run noise.

## Credits

This project borrows heavily from the original pelite pattern model and syntax.
Huge thanks to CasualX and his pelite project:

- <https://github.com/CasualX/pelite>
- <https://docs.rs/pelite/latest/pelite/pattern/>

## License

Licensed under the MIT License. See `LICENSE` for details.
