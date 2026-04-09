//! Pattern syntax onboarding for pelite-style signatures.
//!
//! `goblin-lite` re-exports the parser from `goblin-lite-pattern` so callers can
//! parse at runtime or use `pattern!` for compile-time parsing.
//!
//! - Full syntax tutorial (canonical): [`parse`]
//! - Scanner onboarding and save-buffer usage: [`crate`]
//! - Runtime scan APIs: [`crate::Scanner`] and [`crate::Matches`]

pub use goblin_lite_pattern::*;
