//! Throughput benchmark for patterns whose strongest literal run is *not* the leading one
//! (the weak-anchor / leading-wildcard case). Scans the real PE64 + ELF64 fixtures via
//! `matches_code`, counting all matches, so it measures the full scan over the code.

use std::{fs, path::PathBuf};

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use goblin_sigscan::{
    elf::ElfFile,
    pattern::{self, Atom},
    pe64::PeFile,
};

const PE64_FIXTURE: &str = "memflow_coredump.x86_64.dll";
const ELF64_FIXTURE: &str = "libmemflow_coredump.x86_64.so";

const PATTERNS: &[(&str, &str)] = &[
    ("weak_lead_two_runs", "48 8b ? ? ? ? 48 89 ? ? ba 2c"),
    ("leading_wildcards", "? ? 48 8b 0d ? ? ? ? 15 7c"),
    ("late_rare_run", "48 8b ? ? ? ? ? ? 0f b6 84"),
    ("strong_lead_control", "55 41 57 41 56"),
];

struct ParsedPattern {
    label: &'static str,
    atoms: Vec<Atom>,
    save_slots: usize,
}

fn parse_patterns() -> Vec<ParsedPattern> {
    PATTERNS
        .iter()
        .map(|(label, source)| {
            let atoms = pattern::parse(source).expect("benchmark pattern should parse");
            let save_slots = pattern::save_len(&atoms);
            ParsedPattern {
                label,
                atoms,
                save_slots,
            }
        })
        .collect()
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
    let patterns = parse_patterns();

    let mut group = c.benchmark_group("scan_anchor_pe64");
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
                        }
                        black_box(total);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_elf64(c: &mut Criterion) {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).expect("ELF fixture should parse");
    let scanner = file.scanner();
    let patterns = parse_patterns();

    let mut group = c.benchmark_group("scan_anchor_elf64");
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
                        }
                        black_box(total);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_pe64, bench_elf64);
criterion_main!(benches);
