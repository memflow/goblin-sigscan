use criterion::{Criterion, black_box, criterion_group, criterion_main};
use goblin_sigscan::pattern;

/// Micro-benchmark for `pattern::parse`. The runtime parser is on the hot path for
/// `prepare_pattern_str` and any per-scan string parsing, so track its cost directly.
fn bench_parse(c: &mut Criterion) {
    let sources = [
        ("literal_wildcards", "48 8b 0d ? ? ? ? 48 89"),
        ("jump4_capture", "e8 ${'}"),
        ("alternation", "(85 c0 | 48 85 c0)"),
        ("reads", "b8 u4 66 b8 u2 6a i1"),
        ("skip_range", "48 8b [3-10] 48 89"),
        ("string", "b8 \"MZ\" 00"),
    ];

    let mut group = c.benchmark_group("parse");
    for (label, source) in sources {
        group.bench_function(label, |b| {
            b.iter(|| {
                let atoms =
                    pattern::parse(black_box(source)).expect("benchmark pattern should parse");
                black_box(atoms);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
