use goblin_sigscan::{pattern, pattern as pat};

#[test]
fn proc_macro_matches_runtime_parser() {
    let runtime = pattern::parse("44 8B 81 u4 48 8D 0D").expect("runtime parser failed");
    let compile_time = pat!("44 8B 81 u4 48 8D 0D");
    assert_eq!(compile_time, runtime.as_slice());
}

#[test]
fn proc_macro_matches_runtime_parser_for_alternatives() {
    let source = "(488d15${'} | 4c8d05${'}) 488d0d${'}";
    let runtime = pattern::parse(source).expect("runtime parser failed");
    let compile_time = pat!("(488d15${'} | 4c8d05${'}) 488d0d${'}");
    assert_eq!(compile_time, runtime.as_slice());
}

#[test]
fn proc_macro_matches_runtime_parser_for_range_skips() {
    let source = "48891d[5-9]4c63b3";
    let runtime = pattern::parse(source).expect("runtime parser failed");
    let compile_time = pat!("48891d[5-9]4c63b3");
    assert_eq!(compile_time, runtime.as_slice());
}

#[test]
fn proc_macro_matches_runtime_parser_for_wildcards() {
    let source = "48 8B ? ? ? ? 48 89";
    let runtime = pattern::parse(source).expect("runtime parser failed");
    let compile_time = pat!("48 8B ? ? ? ? 48 89");
    assert_eq!(compile_time, runtime.as_slice());
}

#[test]
fn proc_macro_matches_runtime_parser_for_string_literals() {
    let source = "\"hello\" 00";
    let runtime = pattern::parse(source).expect("runtime parser failed");
    let compile_time = pat!("\"hello\" 00");
    assert_eq!(compile_time, runtime.as_slice());
}
