//! Pelite-style pattern parser used by `goblin-lite`.
//!
//! This crate parses textual signatures into [`Atom`] instructions that can be
//! executed by scanner implementations.
//! For scanner-facing onboarding and end-to-end examples, see
//! `goblin_lite` crate docs: <https://docs.rs/goblin-lite/latest/goblin_lite/>.
//! The canonical syntax tutorial lives on [`parse`].
//!
//! Cross references:
//! - scanner runtime APIs: `goblin_lite::Scanner` and `goblin_lite::Matches`
//! - prepared scanning path: `goblin_lite::PreparedPattern`

use std::fmt;

const MAX_PATTERN_SOURCE_BYTES: usize = 16 * 1024;
const MAX_PATTERN_ATOMS: usize = u16::MAX as usize;
const MAX_GROUP_ALTERNATIVES: usize = 1024;

/// Pattern parser error.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParsePatError {
    kind: PatError,
    position: usize,
}

impl ParsePatError {
    /// Returns the error kind.
    pub fn kind(self) -> PatError {
        self.kind
    }

    /// Returns the byte offset where parsing failed.
    pub fn position(self) -> usize {
        self.position
    }
}

impl fmt::Display for ParsePatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Syntax Error @{}: {}.",
            self.position,
            self.kind.as_str()
        )
    }
}

impl std::error::Error for ParsePatError {}

/// Pattern parsing error categories.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PatError {
    UnpairedHexDigit,
    UnknownChar,
    UnclosedQuote,
    SaveOverflow,
    ReadOperand,
    SkipOperand,
    GroupOperand,
    StackError,
    StackInvalid,
    PatternTooLong,
    PatternTooComplex,
}

impl PatError {
    fn as_str(self) -> &'static str {
        match self {
            PatError::UnpairedHexDigit => "unpaired hex digit",
            PatError::UnknownChar => "unknown character",
            PatError::UnclosedQuote => "string missing end quote",
            PatError::SaveOverflow => "save store overflow",
            PatError::ReadOperand => "read operand error",
            PatError::SkipOperand => "skip operand error",
            PatError::GroupOperand => "group operand error",
            PatError::StackError => "stack unbalanced",
            PatError::StackInvalid => "stack must follow jump",
            PatError::PatternTooLong => "pattern input too long",
            PatError::PatternTooComplex => "pattern expands beyond supported complexity limits",
        }
    }
}

/// Pattern atoms.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Atom {
    /// Matches a single byte.
    Byte(u8),
    /// Applies a bitmask to the next byte comparison.
    Fuzzy(u8),
    /// Captures the cursor RVA in the save slot.
    Save(u8),
    /// Skips a fixed number of bytes.
    Skip(u8),
    /// Skips a ranged number of bytes (inclusive).
    SkipRange(u16, u16),
    /// Executes a recursive sub-pattern and then resumes at `cursor + skip`.
    Push(u8),
    /// Returns from a recursive sub-pattern.
    Pop,
    /// Follows a signed 1-byte relative jump.
    Jump1,
    /// Follows a signed 4-byte relative jump.
    Jump4,
    /// Follows an absolute pointer.
    Ptr,
    /// Follows a position-independent reference from a saved base slot.
    Pir(u8),
    /// Reads and sign-extends the byte under the cursor, writes to slot, advances by 1.
    ReadI8(u8),
    /// Reads and zero-extends the byte under the cursor, writes to slot, advances by 1.
    ReadU8(u8),
    /// Reads a little-endian `i16`, sign-extends, stores in save slot, advances by 2.
    ReadI16(u8),
    /// Reads a little-endian `u16`, zero-extends, stores in save slot, advances by 2.
    ReadU16(u8),
    /// Reads a little-endian `i32`, sign-extends, stores in save slot, advances by 4.
    ReadI32(u8),
    /// Reads a little-endian `u32`, stores it in save slot, and advances the cursor by 4.
    ReadU32(u8),
    /// Writes zero to the given save slot without advancing the cursor.
    Zero(u8),
    /// Rewinds the cursor by a fixed number of bytes.
    Back(u8),
    /// Fails if the cursor is not aligned to `(1 << value)` bytes.
    Aligned(u8),
    /// Fails if the cursor does not equal the value in the given save slot.
    Check(u8),
    /// Branches to an alternate pattern arm on failure.
    Case(u16),
    /// Jumps past remaining alternate arms when current arm succeeds.
    Break(u16),
    /// No-op instruction used to keep pattern control-flow offsets stable.
    Nop,
}

/// Patterns are a list of [`Atom`]s.
pub type Pattern = Vec<Atom>;

/// Returns the save array length required by the pattern.
pub fn save_len(pat: &[Atom]) -> usize {
    pat.iter()
        .filter_map(|atom| match atom {
            Atom::Save(slot)
            | Atom::ReadI8(slot)
            | Atom::ReadU8(slot)
            | Atom::ReadI16(slot)
            | Atom::ReadU16(slot)
            | Atom::ReadI32(slot)
            | Atom::ReadU32(slot)
            | Atom::Zero(slot)
            | Atom::Check(slot)
            | Atom::Pir(slot) => Some(usize::from(*slot) + 1),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

/// Parses a pelite-style signature string into atoms.
///
/// Parsing injects an implicit `Save(0)` at the beginning so slot `0` always
/// represents the match base cursor for parsed patterns.
///
/// This is the main runtime entry point for pattern text.
///
/// # Syntax tutorial
///
/// Following are examples of the syntax supported by `goblin-lite`.
///
/// ```text
/// 55 89 e5 83 ? ec
/// ```
///
/// Case-insensitive hexadecimal pairs match exact bytes and question marks are
/// wildcard bytes.
///
/// A single `?` matches a full byte. Partial nibble masks are not currently
/// supported.
///
/// Whitespace has no semantic meaning and is only for readability.
///
/// ```text
/// b9 ' 37 13 00 00
/// ```
///
/// A single quote (`'`) stores the current cursor into the next save slot.
///
/// Save slot ordering is deterministic:
///
/// - `save[0]` is always the overall match start (`Save(0)` injected by parser)
/// - `save[1..]` are captures in order of appearance (`'`, `i*`, `u*`, `z`, ...)
///
/// ```text
/// b8 [16] 50 [13-42] ff
/// ```
///
/// Bracket operands skip bytes:
///
/// - `[N]` skips exactly `N` bytes
/// - `[A-B]` tries the range non-greedily (smallest skip first)
///
/// Internally `[A-B]` compiles to `SkipRange(A, B - 1)`.
///
/// ```text
/// 31 c0 74 % ' c3
/// e8 $ ' 31 c0 c3
/// ```
///
/// `%` follows a signed rel8 target and `$` follows a signed rel32 target.
///
/// This composes with captures and read ops to recover referenced addresses and
/// values without manual offset arithmetic.
///
/// ```text
/// e8 $ { ' } 83 f0 5c c3
/// ```
///
/// Curly braces must follow `%`, `$`, or `*`. The sub-pattern inside `{...}` runs at
/// the jump destination. After it succeeds, scanning returns to the original
/// stream position, skips jump bytes, and continues.
///
/// ```text
/// e8 $ @4
/// ```
///
/// `@n` checks alignment at that point in the scan. Alignment is `1 << n`
/// bytes, so `@4` means 16-byte alignment.
///
/// ```text
/// e8 i1 a0 u4 z
/// ```
///
/// `i`/`u` read memory into save slots and advance the cursor by operand size:
///
/// - signed reads: `i1`, `i2`, `i4`
/// - unsigned reads: `u1`, `u2`, `u4`
/// - `z` writes a literal zero to a fresh slot
///
/// ```text
/// 83 c0 2a ( 6a ? | 68 ? ? ? ? ) e8
/// ```
///
/// Parentheses define alternatives separated by `|`. Arms are attempted from
/// left to right and the pattern fails only if every arm fails.
///
/// ```text
/// b8 "MZ" 00
/// ```
///
/// Double-quoted strings emit literal byte sequences.
///
/// ## Pelite compatibility notes
///
/// `goblin-lite` intentionally tracks a practical subset of pelite syntax.
///
/// - Supported: hex bytes, `?`, `'`, `%`, `$`, `*`, `{...}`, `[N]`, `[A-B]`, `@n`,
///   `i1/i2/i4`, `u1/u2/u4`, `z`, alternation, and strings.
/// - Programmatic-only atoms (not parser syntax): `Pir(slot)`.
///
/// # Save-slot semantics
///
/// `parse` always prepends `Save(0)`, so parsed patterns always require at
/// least one save slot. Use [`save_len`] to allocate scanner buffers.
///
/// If you are calling scanner APIs from `goblin-lite`, this means `save[0]`
/// is always the match start for parsed patterns.
///
/// # Examples
///
/// ```
/// use goblin_lite_pattern::{Atom, parse, save_len};
///
/// let atoms = parse("48 8B ? ? ? ? 48 89")?;
/// assert_eq!(atoms.first(), Some(&Atom::Save(0)));
/// assert_eq!(save_len(&atoms), 1);
/// # Ok::<(), goblin_lite_pattern::ParsePatError>(())
/// ```
///
/// Capturing a jump target plus a post-jump cursor capture:
///
/// ```
/// use goblin_lite_pattern::{Atom, parse, save_len};
///
/// let atoms = parse("e8 ${'}")?;
/// assert!(matches!(atoms[0], Atom::Save(0)));
/// assert!(atoms.iter().any(|atom| matches!(atom, Atom::Jump4)));
/// assert!(save_len(&atoms) >= 2);
/// # Ok::<(), goblin_lite_pattern::ParsePatError>(())
/// ```
///
/// Group alternatives:
///
/// ```
/// use goblin_lite_pattern::{Atom, parse};
///
/// let atoms = parse("(85 c0 | 48 85 c0)")?;
/// assert!(atoms.iter().any(|atom| matches!(atom, Atom::Case(_))));
/// assert!(atoms.iter().any(|atom| matches!(atom, Atom::Break(_))));
/// # Ok::<(), goblin_lite_pattern::ParsePatError>(())
/// ```
///
/// # Errors
///
/// Returns [`ParsePatError`] with:
///
/// - a kind ([`PatError`])
/// - a byte position in the source string
///
/// Common error kinds include:
///
/// - [`PatError::UnpairedHexDigit`]
/// - [`PatError::SkipOperand`]
/// - [`PatError::ReadOperand`]
/// - [`PatError::GroupOperand`]
/// - [`PatError::PatternTooLong`]
/// - [`PatError::PatternTooComplex`]
///
/// # Quick compile-checked examples
///
/// ```
/// use goblin_lite_pattern::{Atom, parse, save_len};
///
/// let atoms = parse("48 8B ? ? ? ? 48 89")?;
/// assert_eq!(atoms.first(), Some(&Atom::Save(0)));
/// assert_eq!(save_len(&atoms), 1);
/// # Ok::<(), goblin_lite_pattern::ParsePatError>(())
/// ```
///
/// ```
/// use goblin_lite_pattern::{Atom, parse, save_len};
///
/// let atoms = parse("e8 ${'}")?;
/// assert!(matches!(atoms[0], Atom::Save(0)));
/// assert!(atoms.iter().any(|atom| matches!(atom, Atom::Jump4)));
/// assert!(save_len(&atoms) >= 2);
/// # Ok::<(), goblin_lite_pattern::ParsePatError>(())
/// ```
///
/// ```
/// use goblin_lite_pattern::{Atom, parse};
///
/// let atoms = parse("(85 c0 | 48 85 c0)")?;
/// assert!(atoms.iter().any(|atom| matches!(atom, Atom::Case(_))));
/// assert!(atoms.iter().any(|atom| matches!(atom, Atom::Break(_))));
/// # Ok::<(), goblin_lite_pattern::ParsePatError>(())
/// ```
pub fn parse(pat: &str) -> Result<Pattern, ParsePatError> {
    if pat.len() > MAX_PATTERN_SOURCE_BYTES {
        return Err(ParsePatError {
            kind: PatError::PatternTooLong,
            position: MAX_PATTERN_SOURCE_BYTES,
        });
    }

    let mut parser = Parser::new(pat);
    let mut result = Vec::with_capacity(pat.len() / 2);
    result.push(Atom::Save(0));
    result.append(&mut parser.parse_sequence(&[])?);

    if result.len() > MAX_PATTERN_ATOMS {
        return Err(ParsePatError {
            kind: PatError::PatternTooComplex,
            position: pat.len(),
        });
    }

    while matches!(result.last(), Some(Atom::Skip(_))) {
        result.pop();
    }

    if parser.depth != 0 {
        return Err(ParsePatError {
            kind: PatError::StackError,
            position: pat.len(),
        });
    }
    if parser.peek().is_some() {
        return Err(ParsePatError {
            kind: PatError::GroupOperand,
            position: parser.peek().map(|(pos, _)| pos).unwrap_or(pat.len()),
        });
    }

    Ok(result)
}

struct Parser<'a> {
    chars: Vec<(usize, char)>,
    cursor: usize,
    save: u8,
    depth: u16,
    _source: &'a str,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            chars: source.char_indices().collect(),
            cursor: 0,
            save: 1,
            depth: 0,
            _source: source,
        }
    }

    fn parse_sequence(&mut self, stoppers: &[char]) -> Result<Vec<Atom>, ParsePatError> {
        let mut result = Vec::new();

        while let Some((position, ch)) = self.peek() {
            if stoppers.contains(&ch) {
                break;
            }

            self.bump();
            match ch {
                ' ' | '\n' | '\r' | '\t' => {}
                '?' => {
                    push_skip(&mut result, 1);
                }
                '[' => self.parse_skip_operand(position, &mut result)?,
                '\'' => {
                    if self.save == u8::MAX {
                        return Err(ParsePatError {
                            kind: PatError::SaveOverflow,
                            position,
                        });
                    }
                    result.push(Atom::Save(self.save));
                    self.save += 1;
                }
                '%' => result.push(Atom::Jump1),
                '$' => result.push(Atom::Jump4),
                '*' => result.push(Atom::Ptr),
                '"' => {
                    let mut closed = false;
                    while let Some((_, next)) = self.bump() {
                        if next == '"' {
                            closed = true;
                            break;
                        }
                        if !next.is_ascii() {
                            return Err(ParsePatError {
                                kind: PatError::UnknownChar,
                                position,
                            });
                        }
                        result.push(Atom::Byte(next as u8));
                    }
                    if !closed {
                        return Err(ParsePatError {
                            kind: PatError::UnclosedQuote,
                            position,
                        });
                    }
                }
                '{' => {
                    if self.depth == u16::MAX {
                        return Err(ParsePatError {
                            kind: PatError::StackError,
                            position,
                        });
                    }
                    self.depth += 1;
                    let Some(last) = result.last_mut() else {
                        return Err(ParsePatError {
                            kind: PatError::StackInvalid,
                            position,
                        });
                    };
                    let replaced = match *last {
                        Atom::Jump1 => {
                            *last = Atom::Push(1);
                            Atom::Jump1
                        }
                        Atom::Jump4 => {
                            *last = Atom::Push(4);
                            Atom::Jump4
                        }
                        Atom::Ptr => {
                            *last = Atom::Push(0);
                            Atom::Ptr
                        }
                        _ => {
                            return Err(ParsePatError {
                                kind: PatError::StackInvalid,
                                position,
                            });
                        }
                    };
                    result.push(replaced);
                }
                '}' => {
                    if self.depth == 0 {
                        return Err(ParsePatError {
                            kind: PatError::StackError,
                            position,
                        });
                    }
                    self.depth -= 1;
                    result.push(Atom::Pop);
                }
                'i' | 'u' => {
                    let signed = ch == 'i';
                    let (_, op) = self.bump().ok_or(ParsePatError {
                        kind: PatError::ReadOperand,
                        position,
                    })?;
                    if self.save == u8::MAX {
                        return Err(ParsePatError {
                            kind: PatError::SaveOverflow,
                            position,
                        });
                    }
                    let slot = self.save;
                    self.save += 1;
                    let atom = match (signed, op) {
                        (true, '1') => Atom::ReadI8(slot),
                        (false, '1') => Atom::ReadU8(slot),
                        (true, '2') => Atom::ReadI16(slot),
                        (false, '2') => Atom::ReadU16(slot),
                        (true, '4') => Atom::ReadI32(slot),
                        (false, '4') => Atom::ReadU32(slot),
                        _ => {
                            return Err(ParsePatError {
                                kind: PatError::ReadOperand,
                                position,
                            });
                        }
                    };
                    result.push(atom);
                }
                'z' => {
                    if self.save == u8::MAX {
                        return Err(ParsePatError {
                            kind: PatError::SaveOverflow,
                            position,
                        });
                    }
                    result.push(Atom::Zero(self.save));
                    self.save += 1;
                }
                '@' => {
                    let (next_pos, op) = self.bump().ok_or(ParsePatError {
                        kind: PatError::ReadOperand,
                        position,
                    })?;
                    let align = match op {
                        '0'..='9' => op as u8 - b'0',
                        'A'..='Z' => 10 + (op as u8 - b'A'),
                        'a'..='z' => 10 + (op as u8 - b'a'),
                        _ => {
                            return Err(ParsePatError {
                                kind: PatError::ReadOperand,
                                position: next_pos,
                            });
                        }
                    };
                    result.push(Atom::Aligned(align));
                }
                '(' => {
                    let alts = self.parse_group(position)?;
                    result.append(&mut compile_alternatives(alts, position)?);
                }
                _ if ch.is_ascii_hexdigit() => {
                    let (next_position, lo_ch) = self.bump().ok_or(ParsePatError {
                        kind: PatError::UnpairedHexDigit,
                        position,
                    })?;
                    if !lo_ch.is_ascii_hexdigit() {
                        return Err(ParsePatError {
                            kind: PatError::UnpairedHexDigit,
                            position: next_position,
                        });
                    }
                    let hi = hex_value(ch).expect("ascii hex already validated");
                    let lo = hex_value(lo_ch).expect("ascii hex already validated");
                    result.push(Atom::Byte((hi << 4) | lo));
                }
                _ => {
                    return Err(ParsePatError {
                        kind: PatError::UnknownChar,
                        position,
                    });
                }
            }

            if result.len() > MAX_PATTERN_ATOMS {
                return Err(ParsePatError {
                    kind: PatError::PatternTooComplex,
                    position,
                });
            }
        }

        Ok(result)
    }

    fn parse_group(&mut self, position: usize) -> Result<Vec<Vec<Atom>>, ParsePatError> {
        let mut alternatives = Vec::new();
        let group_save = self.save;
        let group_depth = self.depth;
        let mut max_save = self.save;
        loop {
            self.save = group_save;
            self.depth = group_depth;
            let seq = self.parse_sequence(&['|', ')'])?;
            max_save = max_save.max(self.save);
            alternatives.push(seq);
            if alternatives.len() > MAX_GROUP_ALTERNATIVES {
                return Err(ParsePatError {
                    kind: PatError::PatternTooComplex,
                    position,
                });
            }

            let Some((stop_pos, stop)) = self.bump() else {
                return Err(ParsePatError {
                    kind: PatError::GroupOperand,
                    position,
                });
            };

            match stop {
                '|' => continue,
                ')' => break,
                _ => {
                    return Err(ParsePatError {
                        kind: PatError::GroupOperand,
                        position: stop_pos,
                    });
                }
            }
        }

        if alternatives.is_empty() {
            return Err(ParsePatError {
                kind: PatError::GroupOperand,
                position,
            });
        }

        self.save = max_save;
        self.depth = group_depth;

        Ok(alternatives)
    }

    fn parse_skip_operand(
        &mut self,
        position: usize,
        result: &mut Vec<Atom>,
    ) -> Result<(), ParsePatError> {
        let mut first: u32 = 0;
        let mut second: u32 = 0;
        let mut saw_first = false;
        let mut saw_second = false;
        let mut ranged = false;

        while let Some((_, ch)) = self.bump() {
            match ch {
                '0'..='9' => {
                    let digit = u32::from(ch as u8 - b'0');
                    if !ranged {
                        saw_first = true;
                        first = first
                            .checked_mul(10)
                            .and_then(|n| n.checked_add(digit))
                            .ok_or(ParsePatError {
                                kind: PatError::SkipOperand,
                                position,
                            })?;
                    } else {
                        saw_second = true;
                        second = second
                            .checked_mul(10)
                            .and_then(|n| n.checked_add(digit))
                            .ok_or(ParsePatError {
                                kind: PatError::SkipOperand,
                                position,
                            })?;
                    }
                }
                '-' => {
                    if ranged || !saw_first {
                        return Err(ParsePatError {
                            kind: PatError::SkipOperand,
                            position,
                        });
                    }
                    ranged = true;
                }
                ']' => {
                    if !saw_first {
                        return Err(ParsePatError {
                            kind: PatError::SkipOperand,
                            position,
                        });
                    }
                    if !ranged {
                        push_skip(result, first);
                        return Ok(());
                    }
                    if !saw_second || second <= first {
                        return Err(ParsePatError {
                            kind: PatError::SkipOperand,
                            position,
                        });
                    }
                    let min = u16::try_from(first).map_err(|_| ParsePatError {
                        kind: PatError::SkipOperand,
                        position,
                    })?;
                    let max = u16::try_from(second - 1).map_err(|_| ParsePatError {
                        kind: PatError::SkipOperand,
                        position,
                    })?;
                    result.push(Atom::SkipRange(min, max));
                    return Ok(());
                }
                _ => {
                    return Err(ParsePatError {
                        kind: PatError::SkipOperand,
                        position,
                    });
                }
            }
        }

        Err(ParsePatError {
            kind: PatError::SkipOperand,
            position,
        })
    }

    fn peek(&self) -> Option<(usize, char)> {
        self.chars.get(self.cursor).copied()
    }

    fn bump(&mut self) -> Option<(usize, char)> {
        let value = self.peek()?;
        self.cursor += 1;
        Some(value)
    }
}

fn compile_alternatives(
    mut alts: Vec<Vec<Atom>>,
    position: usize,
) -> Result<Vec<Atom>, ParsePatError> {
    debug_assert!(!alts.is_empty(), "alternatives parser guarantees non-empty");
    if alts.len() == 1 {
        let only = alts
            .pop()
            .expect("alternatives parser guarantees exactly one arm remains");
        return Ok(only);
    }

    let first = alts.remove(0);
    let rest = compile_alternatives(alts, position)?;
    let case_skip = u16::try_from(first.len() + 2).map_err(|_| ParsePatError {
        kind: PatError::PatternTooComplex,
        position,
    })?;
    let break_skip = u16::try_from(rest.len()).map_err(|_| ParsePatError {
        kind: PatError::PatternTooComplex,
        position,
    })?;

    let mut out = Vec::with_capacity(2 + first.len() + rest.len());
    out.push(Atom::Case(case_skip));
    out.extend(first);
    out.push(Atom::Break(break_skip));
    out.extend(rest);
    if out.len() > MAX_PATTERN_ATOMS {
        return Err(ParsePatError {
            kind: PatError::PatternTooComplex,
            position,
        });
    }
    Ok(out)
}

fn hex_value(ch: char) -> Option<u8> {
    match ch {
        '0'..='9' => Some(ch as u8 - b'0'),
        'a'..='f' => Some(ch as u8 - b'a' + 10),
        'A'..='F' => Some(ch as u8 - b'A' + 10),
        _ => None,
    }
}

fn push_skip(result: &mut Vec<Atom>, mut remaining: u32) {
    while remaining != 0 {
        let chunk = u8::try_from(remaining.min(u32::from(u8::MAX))).expect("chunk is bounded");
        remaining -= u32::from(chunk);

        if let Some(Atom::Skip(prev)) = result.last_mut() {
            let free = u8::MAX - *prev;
            if free != 0 {
                let to_add = free.min(chunk);
                *prev += to_add;
                let leftover = chunk - to_add;
                if leftover != 0 {
                    result.push(Atom::Skip(leftover));
                }
                continue;
            }
        }

        result.push(Atom::Skip(chunk));
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{Atom, ParsePatError, PatError, parse};

    #[test]
    fn parses_used_subset() {
        assert_eq!(
            parse("488915${'} 488942"),
            Ok(vec![
                Atom::Save(0),
                Atom::Byte(0x48),
                Atom::Byte(0x89),
                Atom::Byte(0x15),
                Atom::Push(4),
                Atom::Jump4,
                Atom::Save(1),
                Atom::Pop,
                Atom::Byte(0x48),
                Atom::Byte(0x89),
                Atom::Byte(0x42),
            ])
        );

        assert_eq!(
            parse("68*'31c0c3"),
            Ok(vec![
                Atom::Save(0),
                Atom::Byte(0x68),
                Atom::Ptr,
                Atom::Save(1),
                Atom::Byte(0x31),
                Atom::Byte(0xc0),
                Atom::Byte(0xc3),
            ])
        );

        assert_eq!(
            parse("*{'90}"),
            Ok(vec![
                Atom::Save(0),
                Atom::Push(0),
                Atom::Ptr,
                Atom::Save(1),
                Atom::Byte(0x90),
                Atom::Pop,
            ])
        );

        assert_eq!(
            parse("44 8B 81 u4 48 8D 0D"),
            Ok(vec![
                Atom::Save(0),
                Atom::Byte(0x44),
                Atom::Byte(0x8B),
                Atom::Byte(0x81),
                Atom::ReadU32(1),
                Atom::Byte(0x48),
                Atom::Byte(0x8D),
                Atom::Byte(0x0D),
            ])
        );

        assert_eq!(
            parse("488b1d${'} 48891d[4] 4c63b3"),
            Ok(vec![
                Atom::Save(0),
                Atom::Byte(0x48),
                Atom::Byte(0x8b),
                Atom::Byte(0x1d),
                Atom::Push(4),
                Atom::Jump4,
                Atom::Save(1),
                Atom::Pop,
                Atom::Byte(0x48),
                Atom::Byte(0x89),
                Atom::Byte(0x1d),
                Atom::Skip(4),
                Atom::Byte(0x4c),
                Atom::Byte(0x63),
                Atom::Byte(0xb3),
            ])
        );

        assert_eq!(
            parse("\"hello\" 00"),
            Ok(vec![
                Atom::Save(0),
                Atom::Byte(b'h'),
                Atom::Byte(b'e'),
                Atom::Byte(b'l'),
                Atom::Byte(b'l'),
                Atom::Byte(b'o'),
                Atom::Byte(0x00),
            ])
        );
    }

    #[test]
    fn reports_error_position() {
        assert_eq!(
            parse("4G") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::UnpairedHexDigit,
                position: 1,
            })
        );

        assert_eq!(
            parse("u8") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::ReadOperand,
                position: 0,
            })
        );

        assert_eq!(
            parse("\"unterminated") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::UnclosedQuote,
                position: 0,
            })
        );
    }

    #[test]
    fn group_alternatives_reset_and_merge_save_state() {
        assert_eq!(
            parse("('41|'42)'"),
            Ok(vec![
                Atom::Save(0),
                Atom::Case(4),
                Atom::Save(1),
                Atom::Byte(0x41),
                Atom::Break(2),
                Atom::Save(1),
                Atom::Byte(0x42),
                Atom::Save(2),
            ])
        );
    }

    #[test]
    fn range_skip_uses_strict_upper_bound() {
        assert_eq!(
            parse("[5-6]"),
            Ok(vec![Atom::Save(0), Atom::SkipRange(5, 5)])
        );

        assert_eq!(
            parse("[5-5]") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::SkipOperand,
                position: 0,
            })
        );
    }

    #[test]
    fn wildcard_semantics_match_pelite() {
        assert_eq!(
            parse("A?") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::UnpairedHexDigit,
                position: 1,
            })
        );

        assert_eq!(parse("?"), Ok(vec![Atom::Save(0)]));
        assert_eq!(parse("??"), Ok(vec![Atom::Save(0)]));

        assert_eq!(
            parse("4183?03"),
            Ok(vec![
                Atom::Save(0),
                Atom::Byte(0x41),
                Atom::Byte(0x83),
                Atom::Skip(1),
                Atom::Byte(0x03),
            ])
        );
    }

    #[test]
    fn supports_aligned_base36_syntax() {
        assert_eq!(parse("@4"), Ok(vec![Atom::Save(0), Atom::Aligned(4)]));
        assert_eq!(parse("@A"), Ok(vec![Atom::Save(0), Atom::Aligned(10)]));
        assert_eq!(parse("@f"), Ok(vec![Atom::Save(0), Atom::Aligned(15)]));
        assert_eq!(parse("@z"), Ok(vec![Atom::Save(0), Atom::Aligned(35)]));

        assert_eq!(
            parse("@") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::ReadOperand,
                position: 0,
            })
        );
        assert_eq!(
            parse("@_") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::ReadOperand,
                position: 1,
            })
        );
        assert_eq!(
            parse("@?") as Result<Vec<Atom>, ParsePatError>,
            Err(ParsePatError {
                kind: PatError::ReadOperand,
                position: 1,
            })
        );
    }

    #[test]
    fn save_len_counts_programmatic_pir_slots() {
        let pat = [Atom::Save(0), Atom::Pir(3)];
        assert_eq!(super::save_len(&pat), 4);
    }

    proptest! {
        #[test]
        fn parsed_patterns_preserve_base_capture_and_slot_bounds(source in "[ -~]{0,128}") {
            if let Ok(atoms) = parse(&source) {
                prop_assert!(!atoms.is_empty());
                prop_assert_eq!(atoms[0], Atom::Save(0));

                let required_slots = super::save_len(&atoms);
                prop_assert!(required_slots >= 1);
                prop_assert!(required_slots <= usize::from(u8::MAX));
            }
        }
    }
}
