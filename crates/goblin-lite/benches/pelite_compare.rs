use std::{fs, path::PathBuf};

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use goblin_lite::{
    pattern::{self as gl_pattern, Atom as GlAtom},
    pe64::PeFile as GoblinPeFile,
};
use pelite::{
    pattern::{self as pelite_pattern, Atom as PeliteAtom},
    pe64::{Pe as _, PeFile as PelitePeFile},
};

const PE64_FIXTURE: &str = "memflow_coredump.x86_64.dll";
const SAVE_SLOTS: usize = 16;

struct PatternCase {
    label: &'static str,
    goblin_atoms: Vec<GlAtom>,
    pelite_atoms: Vec<PeliteAtom>,
    goblin_save_slots: usize,
}

impl PatternCase {
    fn parse(label: &'static str, source: &'static str) -> Self {
        let goblin_atoms =
            gl_pattern::parse(source).expect("goblin-lite benchmark pattern should parse");
        let pelite_atoms =
            pelite_pattern::parse(source).expect("pelite benchmark pattern should parse");
        let goblin_save_slots = gl_pattern::save_len(&goblin_atoms);
        assert!(
            goblin_save_slots <= SAVE_SLOTS,
            "benchmark SAVE_SLOTS must cover pattern save slot count"
        );
        Self {
            label,
            goblin_atoms,
            pelite_atoms,
            goblin_save_slots,
        }
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name)).expect("fixture should be readable")
}

fn bench_pe64_goblin_vs_pelite(c: &mut Criterion) {
    let bytes = fixture_bytes(PE64_FIXTURE);
    let goblin_file =
        GoblinPeFile::from_bytes(&bytes).expect("PE fixture should parse with goblin-lite");
    let goblin_scanner = goblin_file.scanner();

    let pelite_file =
        PelitePeFile::from_bytes(&bytes).expect("PE fixture should parse with pelite");
    let pelite_scanner = pelite_file.scanner();

    let cases = [
        PatternCase::parse("jump4_tiny", "e8 $"),
        PatternCase::parse("jump4", "e8 ${'}"),
        PatternCase::parse("alternation", "(85 c0 | 48 85 c0)"),
        PatternCase::parse("skip_range", "48 8b [3-10] 48 89"),
    ];

    let mut first_group = c.benchmark_group("pe64_compare/first_match");
    first_group.throughput(Throughput::Bytes(bytes.len() as u64));

    for case in &cases {
        first_group.bench_with_input(
            BenchmarkId::new("goblin-lite", case.label),
            case,
            |b, case| {
                b.iter_batched_ref(
                    || [0u64; SAVE_SLOTS],
                    |save| {
                        let mut matches = goblin_scanner.matches_code(&case.goblin_atoms);
                        let found = matches.next(&mut save[..case.goblin_save_slots]);
                        black_box(found);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        first_group.bench_with_input(BenchmarkId::new("pelite", case.label), case, |b, case| {
            b.iter_batched_ref(
                || [0u32; SAVE_SLOTS],
                |save| {
                    let mut matches = pelite_scanner.matches_code(&case.pelite_atoms);
                    let found = matches.next(save);
                    black_box(found);
                },
                BatchSize::SmallInput,
            );
        });
    }

    first_group.finish();

    let mut all_group = c.benchmark_group("pe64_compare/all_matches");
    all_group.throughput(Throughput::Bytes(bytes.len() as u64));

    for case in &cases {
        all_group.bench_with_input(
            BenchmarkId::new("goblin-lite", case.label),
            case,
            |b, case| {
                b.iter_batched_ref(
                    || [0u64; SAVE_SLOTS],
                    |save| {
                        let mut matches = goblin_scanner.matches_code(&case.goblin_atoms);
                        let mut total = 0usize;
                        while matches.next(&mut save[..case.goblin_save_slots]) {
                            total += 1;
                        }
                        black_box(total);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        all_group.bench_with_input(BenchmarkId::new("pelite", case.label), case, |b, case| {
            b.iter_batched_ref(
                || [0u32; SAVE_SLOTS],
                |save| {
                    let mut matches = pelite_scanner.matches_code(&case.pelite_atoms);
                    let mut total = 0usize;
                    while matches.next(save) {
                        total += 1;
                    }
                    black_box(total);
                },
                BatchSize::SmallInput,
            );
        });
    }

    all_group.finish();
}

criterion_group!(benches, bench_pe64_goblin_vs_pelite);
criterion_main!(benches);
