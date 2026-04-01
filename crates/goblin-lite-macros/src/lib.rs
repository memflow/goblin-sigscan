use goblin_lite_pattern::Atom;
use proc_macro::{Delimiter, Literal, TokenStream, TokenTree};
use proc_macro_crate::{FoundCrate, crate_name};

/// Compile-time pattern parser.
///
/// ```no_run
/// use goblin_lite_macros::pattern;
///
/// let _macro_name = stringify!(pattern);
/// ```
#[proc_macro]
pub fn pattern(input: TokenStream) -> TokenStream {
    let mut input = input.into_iter().collect::<Vec<_>>();

    if let [TokenTree::Group(group)] = &input[..]
        && group.delimiter() == Delimiter::None
    {
        input = group.stream().into_iter().collect::<Vec<_>>();
    }

    let literal = match &input[..] {
        [TokenTree::Literal(lit)] => lit,
        _ => panic!("expected a single string literal to parse"),
    };

    let source = parse_str_literal(literal);
    let atoms = goblin_lite_pattern::parse(&source)
        .unwrap_or_else(|err| panic!("invalid pattern syntax: {err}"));
    let crate_root = goblin_lite_crate_root();

    let body = atoms
        .into_iter()
        .map(atom_to_tokens)
        .map(|atom| format!("{crate_root}::pattern::Atom::{atom}"))
        .collect::<Vec<_>>()
        .join(", ");

    format!("&[{body}]")
        .parse()
        .expect("token generation failed")
}

fn goblin_lite_crate_root() -> String {
    match crate_name("goblin-lite") {
        Ok(FoundCrate::Itself) => "crate".to_owned(),
        Ok(FoundCrate::Name(name)) => name.replace('-', "_"),
        Err(err) => panic!("unable to resolve goblin-lite crate for macro expansion: {err}"),
    }
}

fn atom_to_tokens(atom: Atom) -> String {
    match atom {
        Atom::Byte(value) => format!("Byte({value})"),
        Atom::Fuzzy(mask) => format!("Fuzzy({mask})"),
        Atom::Save(slot) => format!("Save({slot})"),
        Atom::Skip(skip) => format!("Skip({skip})"),
        Atom::SkipRange(min, max) => format!("SkipRange({min}, {max})"),
        Atom::Push(skip) => format!("Push({skip})"),
        Atom::Pop => "Pop".to_owned(),
        Atom::Jump1 => "Jump1".to_owned(),
        Atom::Jump4 => "Jump4".to_owned(),
        Atom::ReadI8(slot) => format!("ReadI8({slot})"),
        Atom::ReadU8(slot) => format!("ReadU8({slot})"),
        Atom::ReadI16(slot) => format!("ReadI16({slot})"),
        Atom::ReadU16(slot) => format!("ReadU16({slot})"),
        Atom::ReadI32(slot) => format!("ReadI32({slot})"),
        Atom::ReadU32(slot) => format!("ReadU32({slot})"),
        Atom::Zero(slot) => format!("Zero({slot})"),
        Atom::Back(n) => format!("Back({n})"),
        Atom::Aligned(align) => format!("Aligned({align})"),
        Atom::Check(slot) => format!("Check({slot})"),
        Atom::Case(skip) => format!("Case({skip})"),
        Atom::Break(skip) => format!("Break({skip})"),
        Atom::Nop => "Nop".to_owned(),
    }
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
