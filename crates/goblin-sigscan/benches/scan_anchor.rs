//! Throughput benchmark for patterns whose strongest literal run is *not* the leading one
//! (the weak-anchor / leading-wildcard case). Scans the real PE64 + ELF64 fixtures via
//! `matches_code` (per-call analysis) and `matches_prepared` (reused prepared metadata),
//! counting all matches, so it measures the full scan over the code. A separate group times
//! `prepare_pattern` itself so the one-off preparation cost stays visible.

use std::{fs, path::PathBuf};

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use goblin_sigscan::{
    BinaryView, Scanner,
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

fn bench_scans<B: BinaryView>(
    c: &mut Criterion,
    label: &str,
    bytes_len: usize,
    scanner: Scanner<'_, B>,
    patterns: &[ParsedPattern],
) {
    let mut group = c.benchmark_group(format!("scan_anchor_{label}"));
    group.throughput(Throughput::Bytes(bytes_len as u64));
    for pat in patterns {
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

        // Prepared once outside the timing loop: steady-state reuse is the point of
        // preparation, so this measures the pure scan with prepared metadata.
        let prepared = scanner.prepare_pattern(&pat.atoms);
        group.bench_with_input(
            BenchmarkId::new("matches_prepared", pat.label),
            &prepared,
            |b, prepared| {
                b.iter_batched_ref(
                    || vec![0u64; pat.save_slots],
                    |save| {
                        let mut total = 0usize;
                        let mut matches = scanner.matches_prepared(prepared);
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

    let mut group = c.benchmark_group(format!("prepare_pattern_{label}"));
    for pat in patterns {
        group.bench_with_input(BenchmarkId::new("prepare", pat.label), pat, |b, pat| {
            b.iter(|| black_box(scanner.prepare_pattern(black_box(&pat.atoms))));
        });
    }
    group.finish();
}

fn bench_pe64(c: &mut Criterion) {
    let bytes = fixture_bytes(PE64_FIXTURE);
    let file = PeFile::from_bytes(&bytes).expect("PE fixture should parse");
    bench_scans(c, "pe64", bytes.len(), file.scanner(), &parse_patterns());
}

fn bench_elf64(c: &mut Criterion) {
    let bytes = fixture_bytes(ELF64_FIXTURE);
    let file = ElfFile::from_bytes(&bytes).expect("ELF fixture should parse");
    bench_scans(c, "elf64", bytes.len(), file.scanner(), &parse_patterns());
}

criterion_group!(benches, bench_pe64, bench_elf64);
criterion_main!(benches);
