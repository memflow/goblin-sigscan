use proc_macro::{Delimiter, Literal, TokenStream, TokenTree};

/// Compile-time pattern parser.
///
/// ```ignore
/// use goblin_lite::pattern as pat;
///
/// let pattern = pat!("488915${'} 488942");
/// ```
#[proc_macro]
pub fn pattern(input: TokenStream) -> TokenStream {
    let mut input = input.into_iter().collect::<Vec<_>>();

    match &input[..] {
        [TokenTree::Group(group)] if group.delimiter() == Delimiter::None => {
            input = group.stream().into_iter().collect::<Vec<_>>();
        }
        _ => {}
    }

    let literal = match &input[..] {
        [TokenTree::Literal(lit)] => lit,
        _ => panic!("expected a single string literal to parse"),
    };

    let source = parse_str_literal(literal);
    let atoms =
        parse_pattern(&source).unwrap_or_else(|err| panic!("invalid pattern syntax: {err}"));

    let body = atoms
        .into_iter()
        .map(|atom| {
            format!(
                "::goblin_lite::pattern::Atom::{atom}",
                atom = atom.to_tokens()
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!("&[{body}]")
        .parse()
        .expect("token generation failed")
}

fn parse_str_literal(input: &Literal) -> String {
    let source = input.to_string();
    let mut chars = source.chars();
    let mut result = String::new();

    assert_eq!(
        chars.next(),
        Some('"'),
        "expected string literal starting with a quote"
    );

    loop {
        let ch = match chars.next() {
            Some('\\') => match chars.next() {
                Some('\\') => '\\',
                Some('"') => '"',
                Some('\'') => '\'',
                Some('n') => '\n',
                Some('r') => '\r',
                Some('t') => '\t',
                Some(other) => panic!("unknown escape sequence: {other}"),
                None => panic!("unexpected end of string literal"),
            },
            Some('"') => break,
            Some(ch) => ch,
            None => panic!("unexpected end of string literal"),
        };
        result.push(ch);
    }

    result
}

#[derive(Copy, Clone)]
enum Atom {
    Byte(u8),
    Save(u8),
    Skip(u8),
    Push(u8),
    Pop,
    Jump4,
    ReadU32(u8),
}

impl Atom {
    fn to_tokens(self) -> String {
        match self {
            Atom::Byte(value) => format!("Byte({value})"),
            Atom::Save(slot) => format!("Save({slot})"),
            Atom::Skip(skip) => format!("Skip({skip})"),
            Atom::Push(skip) => format!("Push({skip})"),
            Atom::Pop => "Pop".to_owned(),
            Atom::Jump4 => "Jump4".to_owned(),
            Atom::ReadU32(slot) => format!("ReadU32({slot})"),
        }
    }
}

fn parse_pattern(pat: &str) -> Result<Vec<Atom>, String> {
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
                                .ok_or_else(|| {
                                    format!("Syntax Error @{position}: skip operand error.")
                                })?;
                        }
                        ']' => {
                            found_end = true;
                            break;
                        }
                        _ => {
                            return Err(format!("Syntax Error @{position}: skip operand error."));
                        }
                    }
                }
                if !saw_digit || !found_end {
                    return Err(format!("Syntax Error @{position}: skip operand error."));
                }
                push_skip(&mut result, value);
            }
            '\'' => {
                if save == u8::MAX {
                    return Err(format!("Syntax Error @{position}: save store overflow."));
                }
                result.push(Atom::Save(save));
                save += 1;
            }
            '$' => result.push(Atom::Jump4),
            '{' => {
                depth = depth.saturating_add(1);
                let Some(last) = result.last_mut() else {
                    return Err(format!("Syntax Error @{position}: stack must follow jump."));
                };
                let replaced = match *last {
                    Atom::Jump4 => {
                        *last = Atom::Push(4);
                        Atom::Jump4
                    }
                    _ => return Err(format!("Syntax Error @{position}: stack must follow jump.")),
                };
                result.push(replaced);
            }
            '}' => {
                if depth == 0 {
                    return Err(format!("Syntax Error @{position}: stack unbalanced."));
                }
                depth -= 1;
                result.push(Atom::Pop);
            }
            'u' => {
                let Some((_, op)) = iter.next() else {
                    return Err(format!("Syntax Error @{position}: read operand error."));
                };
                if op != '4' {
                    return Err(format!("Syntax Error @{position}: read operand error."));
                }
                if save == u8::MAX {
                    return Err(format!("Syntax Error @{position}: save store overflow."));
                }
                result.push(Atom::ReadU32(save));
                save += 1;
            }
            _ if ch.is_ascii_hexdigit() => {
                let Some((next_position, lo_ch)) = iter.next() else {
                    return Err(format!("Syntax Error @{position}: unpaired hex digit."));
                };
                if !lo_ch.is_ascii_hexdigit() {
                    return Err(format!(
                        "Syntax Error @{next_position}: unpaired hex digit."
                    ));
                }

                let hi = hex_value(ch).expect("ascii hex already validated");
                let lo = hex_value(lo_ch).expect("ascii hex already validated");
                result.push(Atom::Byte((hi << 4) | lo));
            }
            _ => return Err(format!("Syntax Error @{position}: unknown character.")),
        }
    }

    while matches!(result.last(), Some(Atom::Skip(_))) {
        result.pop();
    }

    if depth != 0 {
        return Err(format!("Syntax Error @{}: stack unbalanced.", pat.len()));
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
