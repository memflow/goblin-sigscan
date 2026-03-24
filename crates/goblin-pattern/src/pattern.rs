use std::fmt;

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
    SaveOverflow,
    ReadOperand,
    SkipOperand,
    StackError,
    StackInvalid,
}

impl PatError {
    fn as_str(self) -> &'static str {
        match self {
            PatError::UnpairedHexDigit => "unpaired hex digit",
            PatError::UnknownChar => "unknown character",
            PatError::SaveOverflow => "save store overflow",
            PatError::ReadOperand => "read operand error",
            PatError::SkipOperand => "skip operand error",
            PatError::StackError => "stack unbalanced",
            PatError::StackInvalid => "stack must follow jump",
        }
    }
}

/// Pattern atoms.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Atom {
    /// Matches a single byte.
    Byte(u8),
    /// Captures the cursor RVA in the save slot.
    Save(u8),
    /// Skips a fixed number of bytes.
    Skip(u8),
    /// Executes a recursive sub-pattern and then resumes at `cursor + skip`.
    Push(u8),
    /// Returns from a recursive sub-pattern.
    Pop,
    /// Follows a signed 4-byte relative jump.
    Jump4,
    /// Reads a little-endian `u32`, stores it in save slot, and advances the cursor by 4.
    ReadU32(u8),
}

/// Patterns are a list of [`Atom`]s.
pub type Pattern = Vec<Atom>;

/// Returns the save array length required by the pattern.
pub fn save_len(pat: &[Atom]) -> usize {
    pat.iter()
        .filter_map(|atom| match atom {
            Atom::Save(slot) | Atom::ReadU32(slot) => Some(usize::from(*slot) + 1),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

/// Parses a pelite-style signature string into atoms.
///
/// Supported syntax in this initial release:
/// - hex bytes (`48 8B 05`)
/// - wildcard byte (`?`)
/// - bookmark (`'`)
/// - follow relative `i32` jump (`$`)
/// - read unsigned dword (`u4`)
pub fn parse(pat: &str) -> Result<Pattern, ParsePatError> {
    let mut result = Vec::with_capacity(pat.len() / 2);
    result.push(Atom::Save(0));

    let mut save: u8 = 1;
    let mut depth: u8 = 0;
    let mut iter = pat.char_indices().peekable();

    while let Some((position, ch)) = iter.next() {
        match ch {
            ' ' | '\n' | '\r' | '\t' => {}
            '?' => {
                push_skip(&mut result, 1);
            }
            '[' => {
                let mut value: u32 = 0;
                let mut saw_digit = false;
                let mut found_end = false;
                for (_, ch) in iter.by_ref() {
                    match ch {
                        '0'..='9' => {
                            saw_digit = true;
                            value = value
                                .checked_mul(10)
                                .and_then(|n| n.checked_add(u32::from(ch as u8 - b'0')))
                                .ok_or(ParsePatError {
                                    kind: PatError::SkipOperand,
                                    position,
                                })?;
                        }
                        ']' => {
                            found_end = true;
                            break;
                        }
                        _ => {
                            return Err(ParsePatError {
                                kind: PatError::SkipOperand,
                                position,
                            });
                        }
                    }
                }
                if !saw_digit || !found_end {
                    return Err(ParsePatError {
                        kind: PatError::SkipOperand,
                        position,
                    });
                }
                push_skip(&mut result, value);
            }
            '\'' => {
                if save == u8::MAX {
                    return Err(ParsePatError {
                        kind: PatError::SaveOverflow,
                        position,
                    });
                }
                result.push(Atom::Save(save));
                save += 1;
            }
            '$' => result.push(Atom::Jump4),
            '{' => {
                depth = depth.saturating_add(1);
                let Some(last) = result.last_mut() else {
                    return Err(ParsePatError {
                        kind: PatError::StackInvalid,
                        position,
                    });
                };
                let replaced = match *last {
                    Atom::Jump4 => {
                        *last = Atom::Push(4);
                        Atom::Jump4
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
                if depth == 0 {
                    return Err(ParsePatError {
                        kind: PatError::StackError,
                        position,
                    });
                }
                depth -= 1;
                result.push(Atom::Pop);
            }
            'u' => {
                let Some((_, op)) = iter.next() else {
                    return Err(ParsePatError {
                        kind: PatError::ReadOperand,
                        position,
                    });
                };
                if op != '4' {
                    return Err(ParsePatError {
                        kind: PatError::ReadOperand,
                        position,
                    });
                }
                if save == u8::MAX {
                    return Err(ParsePatError {
                        kind: PatError::SaveOverflow,
                        position,
                    });
                }
                result.push(Atom::ReadU32(save));
                save += 1;
            }
            _ if ch.is_ascii_hexdigit() => {
                let Some((next_position, lo_ch)) = iter.next() else {
                    return Err(ParsePatError {
                        kind: PatError::UnpairedHexDigit,
                        position,
                    });
                };
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
    }

    while matches!(result.last(), Some(Atom::Skip(_))) {
        result.pop();
    }

    if depth != 0 {
        return Err(ParsePatError {
            kind: PatError::StackError,
            position: pat.len(),
        });
    }

    Ok(result)
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
    }

    #[test]
    fn reports_error_position() {
        assert_eq!(
            parse("4?") as Result<Vec<Atom>, ParsePatError>,
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
    }
}
