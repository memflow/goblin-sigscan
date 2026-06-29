use goblin_sigscan_pattern::Atom;
use proc_macro::{Delimiter, Literal, TokenStream, TokenTree};
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::quote;

/// Compile-time pattern parser.
///
/// ```no_run
/// use goblin_sigscan_macros::pattern;
///
/// let _macro_name = stringify!(pattern);
/// ```
#[proc_macro]
pub fn pattern(input: TokenStream) -> TokenStream {
    // Report misuse as a `compile_error!` at the call site rather than panicking the
    // compiler, which produces a far clearer diagnostic for the user.
    match expand(input) {
        Ok(tokens) => tokens,
        Err(message) => compile_error(&message),
    }
}

fn expand(input: TokenStream) -> Result<TokenStream, String> {
    let mut input = input.into_iter().collect::<Vec<_>>();

    if let [TokenTree::Group(group)] = &input[..]
        && group.delimiter() == Delimiter::None
    {
        input = group.stream().into_iter().collect::<Vec<_>>();
    }

    let literal = match &input[..] {
        [TokenTree::Literal(lit)] => lit,
        _ => return Err("pattern! expects a single string literal".to_owned()),
    };

    let source = parse_str_literal(literal)?;
    let atoms = goblin_sigscan_pattern::parse(&source)
        .map_err(|err| format!("invalid pattern syntax: {err}"))?;
    let crate_root = goblin_sigscan_crate_root();
    let elements: Vec<TokenStream2> = atoms
        .iter()
        .map(|atom| atom_to_tokens(&crate_root, *atom))
        .collect();

    Ok(quote! { &[#(#elements),*] }.into())
}

/// Builds a `::core::compile_error!("…")` invocation carrying `message`.
fn compile_error(message: &str) -> TokenStream {
    quote! { ::core::compile_error!(#message) }.into()
}

fn goblin_sigscan_crate_root() -> Ident {
    let name = match crate_name("goblin-sigscan") {
        Ok(FoundCrate::Itself) => "goblin_sigscan".to_owned(),
        Ok(FoundCrate::Name(name)) => name.replace('-', "_"),
        Err(err) => panic!("unable to resolve goblin-sigscan crate for macro expansion: {err}"),
    };
    Ident::new(&name, Span::call_site())
}

/// Emits `<crate>::pattern::Atom::Variant(args)` for one atom.
fn atom_to_tokens(crate_root: &Ident, atom: Atom) -> TokenStream2 {
    let path = quote! { #crate_root::pattern::Atom };
    match atom {
        Atom::Byte(value) => quote! { #path::Byte(#value) },
        Atom::Fuzzy(mask) => quote! { #path::Fuzzy(#mask) },
        Atom::Save(slot) => quote! { #path::Save(#slot) },
        Atom::Skip(skip) => quote! { #path::Skip(#skip) },
        Atom::SkipRange(min, max) => quote! { #path::SkipRange(#min, #max) },
        Atom::Push(skip) => quote! { #path::Push(#skip) },
        Atom::Pop => quote! { #path::Pop },
        Atom::Jump1 => quote! { #path::Jump1 },
        Atom::Jump4 => quote! { #path::Jump4 },
        Atom::Ptr => quote! { #path::Ptr },
        Atom::Pir(slot) => quote! { #path::Pir(#slot) },
        Atom::ReadI8(slot) => quote! { #path::ReadI8(#slot) },
        Atom::ReadU8(slot) => quote! { #path::ReadU8(#slot) },
        Atom::ReadI16(slot) => quote! { #path::ReadI16(#slot) },
        Atom::ReadU16(slot) => quote! { #path::ReadU16(#slot) },
        Atom::ReadI32(slot) => quote! { #path::ReadI32(#slot) },
        Atom::ReadU32(slot) => quote! { #path::ReadU32(#slot) },
        Atom::Zero(slot) => quote! { #path::Zero(#slot) },
        Atom::Back(n) => quote! { #path::Back(#n) },
        Atom::Aligned(align) => quote! { #path::Aligned(#align) },
        Atom::Check(slot) => quote! { #path::Check(#slot) },
        Atom::Case(skip) => quote! { #path::Case(#skip) },
        Atom::Break(skip) => quote! { #path::Break(#skip) },
        Atom::Nop => quote! { #path::Nop },
    }
}

fn parse_str_literal(input: &Literal) -> Result<String, String> {
    let source = input.to_string();
    let mut chars = source.chars();
    let mut result = String::new();

    if chars.next() != Some('"') {
        return Err("pattern! expects a string literal".to_owned());
    }

    loop {
        let ch = match chars.next() {
            Some('\\') => match chars.next() {
                Some('\\') => '\\',
                Some('"') => '"',
                Some('\'') => '\'',
                Some('n') => '\n',
                Some('r') => '\r',
                Some('t') => '\t',
                Some(other) => return Err(format!("unknown escape sequence: \\{other}")),
                None => return Err("unexpected end of string literal".to_owned()),
            },
            Some('"') => break,
            Some(ch) => ch,
            None => return Err("unexpected end of string literal".to_owned()),
        };
        result.push(ch);
    }

    Ok(result)
}
