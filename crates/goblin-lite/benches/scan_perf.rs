use std::{fs, path::PathBuf};

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use goblin_lite::{
    elf::ElfFile,
    pattern::{self, Atom},
    pe64::PeFile,
};

const PE64_FIXTURE: &str = "memflow_coredump.x86_64.dll";
const ELF64_FIXTURE: &str = "libmemflow_coredump.x86_64.so";

struct ParsedPattern {
    label: &'static str,
    atoms: Vec<Atom>,
    save_slots: usize,
}

impl ParsedPattern {
    fn parse(label: &'static str, source: &'static str) -> Self {
        let atoms = pattern::parse(source).expect("benchmark pattern should parse");
        let save_slots = pattern::save_len(&atoms);
        Self {
            label,
            atoms,
            save_slots,
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

fn bench_pe64(c: &mut Criterion) {
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).expect("PE fixture should parse");
    let scanner = file.scanner();
    let patterns = [
        ParsedPattern::parse("jump4", "e8 ${'}"),
        ParsedPattern::parse("skip_range", "48 8b [3-10] 48 89"),
        ParsedPattern::parse("alternation", "(85 c0 | 48 85 c0)"),
        ParsedPattern::parse("aligned", "@4 48 8b 2d"),
    ];

    let mut group = c.benchmark_group("scan_pe64");
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    for pat in &patterns {
        group.bench_with_input(
            BenchmarkId::new("matches_code", pat.label),
            pat,
            |b, pat| {
                b.iter_batched_ref(
                    || vec![0u64; pat.save_slots],
                    |save| {
                        let mut total = 0usize;
                        let mut matches = scanner.matches_code(&pat.atoms);
                        while matches.next(save) {
                            total += 1;
                            black_box(save[0]);
                        }
                        black_box(total);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(BenchmarkId::new("finds_code", pat.label), pat, |b, pat| {
            b.iter_batched_ref(
                || vec![0u64; pat.save_slots],
                |save| {
                    let found = scanner.finds_code(&pat.atoms, save);
                    black_box(found);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_elf64(c: &mut Criterion) {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).expect("ELF fixture should parse");
    let scanner = file.scanner();
    let patterns = [
        ParsedPattern::parse("prologue", "55 41 57 41 56 41 55 41 54 53 48 83"),
        ParsedPattern::parse("jump1", "48 85 c0 74 %'"),
        ParsedPattern::parse("push_pop", "e8 ${41 57} 48"),
        ParsedPattern::parse("alternation", "(85 c0 | 48 85 c0)"),
    ];

    let mut group = c.benchmark_group("scan_elf64");
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    for pat in &patterns {
        group.bench_with_input(
            BenchmarkId::new("matches_code", pat.label),
            pat,
            |b, pat| {
                b.iter_batched_ref(
                    || vec![0u64; pat.save_slots],
                    |save| {
                        let mut total = 0usize;
                        let mut matches = scanner.matches_code(&pat.atoms);
                        while matches.next(save) {
                            total += 1;
                            black_box(save[0]);
                        }
                        black_box(total);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(BenchmarkId::new("finds_code", pat.label), pat, |b, pat| {
            b.iter_batched_ref(
                || vec![0u64; pat.save_slots],
                |save| {
                    let found = scanner.finds_code(&pat.atoms, save);
                    black_box(found);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_pe64, bench_elf64);
criterion_main!(benches);
