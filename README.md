# goblin-lite

`goblin-lite` provides pelite-style pattern parsing and scanner behavior over
goblin-backed PE/ELF/Mach binaries.

## Workspace crates

- `crates/goblin-lite-pattern`: pattern parser and atom model
- `crates/goblin-lite`: scanner/runtime API and format wrappers
- `crates/goblin-lite-macros`: `pattern!` compile-time parsing macro

## Quick start

```rust
use goblin_lite::pattern;

let atoms = pattern::parse("48 8B ? ? ? ? 48 89")?;
let save_slots = pattern::save_len(&atoms);
assert!(save_slots >= 1);
# Ok::<(), goblin_lite::pattern::ParsePatError>(())
```

When scanning, size `save` buffers with `pattern::save_len(&atoms)` (or
`PreparedPattern::required_slots()`) and treat slot `0` as match base for
parsed patterns.

For syntax onboarding, see the public docs on `goblin_lite::pattern` and
`goblin_lite_pattern::parse`.

Docs.rs navigation shortcuts:

- crate tutorial: <https://docs.rs/goblin-lite/latest/goblin_lite/>
- pattern module: <https://docs.rs/goblin-lite/latest/goblin_lite/pattern/>
- parser crate: <https://docs.rs/goblin-lite-pattern/latest/goblin_lite_pattern/>

## Benchmarks

See `scripts/README.md` for benchmark workflows, A/B comparisons, and guidance
for reducing run-to-run noise.

## Credits

This project borrows heavily from the original pelite pattern model and syntax.
Huge thanks to casualx and the pelite project:

- <https://github.com/CasualX/pelite>
- <https://docs.rs/pelite/latest/pelite/pattern/>

## License

Licensed under the MIT License. See `LICENSE` for details.
