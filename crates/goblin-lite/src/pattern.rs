//! Pattern syntax onboarding for pelite-style signatures.
//!
//! `goblin-lite` re-exports the parser from `goblin-lite-pattern` so callers can
//! parse at runtime or use `pattern!` for compile-time parsing.
//! See the full scanner walkthrough in the crate tutorial at [`crate`].
//!
//! # Quick Start
//!
//! ```
//! use goblin_lite::pattern;
//!
//! let atoms = pattern::parse("48 8B ? ? ? ? 48 89")?;
//! assert!(atoms.len() >= 3);
//! # Ok::<(), pattern::ParsePatError>(())
//! ```
//!
//! Use [`save_len`] to size the `save` buffer passed to scanner APIs:
//!
//! ```
//! use goblin_lite::pattern;
//!
//! let atoms = pattern::parse("e8 ${'}")?;
//! let slots = pattern::save_len(&atoms);
//! assert!(slots >= 2);
//! # Ok::<(), pattern::ParsePatError>(())
//! ```
//!
//! # Save-slot semantics
//!
//! For patterns parsed by [`parse`] (and therefore by `pattern!`), slot `0` is
//! always the base cursor for each match because parsing injects an implicit
//! `Save(0)`.
//!
//! - Slot `0`: match start offset (RVA/VA/mapped offset depending on file type)
//! - Slot `1+`: additional captures from `'`, `i1/i2/i4`, `u1/u2/u4`, `z`, etc.
//! - Required length: exactly `save_len(&atoms)` (or larger)
//!
//! If you pass a larger `save` buffer to scanner APIs, only the required prefix
//! is written and any tail elements are left unchanged.
//!
//! # Syntax at a glance
//!
//! - Hex byte: `48 8B 05`
//! - Wildcard byte: `?` or `??`
//! - Capture cursor: `'`
//! - Relative jumps: `%` (rel8), `$` (rel32)
//! - Read immediates: `i1/i2/i4`, `u1/u2/u4`
//! - Fixed skip: `[5]`
//! - Ranged skip: `[3-10]`
//! - Group alternatives: `(AA BB | CC DD)`
//! - Alignment check: `@4` (cursor must be 16-byte aligned)
//! - String bytes: `"MZ"`
//!
//! See [`parse`] and [`Atom`] for full details, and [`crate::Scanner`] /
//! [`crate::Matches`] for scan execution semantics.

pub use goblin_lite_pattern::*;
