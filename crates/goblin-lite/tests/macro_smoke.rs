use goblin_lite::{pattern, pattern as pat};

#[test]
fn proc_macro_matches_runtime_parser() {
    let runtime = pattern::parse("44 8B 81 u4 48 8D 0D").expect("runtime parser failed");
    let compile_time = pat!("44 8B 81 u4 48 8D 0D");
    assert_eq!(compile_time, runtime.as_slice());
}
