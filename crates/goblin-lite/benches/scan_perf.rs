use std::{fs, path::PathBuf};

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
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

#[derive(Default)]
struct PatternShape {
    bytes: usize,
    jumps: usize,
    skips: usize,
    reads: usize,
    control: usize,
    saves: usize,
    checks: usize,
    linear: bool,
    tiny_literal_jump: bool,
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

fn classify_shape(atoms: &[Atom]) -> PatternShape {
    let mut shape = PatternShape {
        linear: true,
        tiny_literal_jump: true,
        ..PatternShape::default()
    };
    let mut has_jump = false;
    for atom in atoms {
        match atom {
            Atom::Byte(_) => shape.bytes += 1,
            Atom::Jump1 | Atom::Jump4 => {
                shape.jumps += 1;
                has_jump = true;
            }
            Atom::Skip(_) => shape.skips += 1,
            Atom::ReadI8(_)
            | Atom::ReadU8(_)
            | Atom::ReadI16(_)
            | Atom::ReadU16(_)
            | Atom::ReadI32(_)
            | Atom::ReadU32(_) => shape.reads += 1,
            Atom::Case(_) | Atom::Break(_) | Atom::Push(_) | Atom::Pop | Atom::SkipRange(_, _) => {
                shape.control += 1;
                shape.linear = false;
            }
            Atom::Save(_) => shape.saves += 1,
            Atom::Check(_) => shape.checks += 1,
            Atom::Nop => {}
            Atom::Fuzzy(_) | Atom::Zero(_) | Atom::Back(_) | Atom::Aligned(_) => {
                shape.tiny_literal_jump = false;
            }
        }
        match atom {
            Atom::Byte(_)
            | Atom::Save(_)
            | Atom::Skip(_)
            | Atom::Jump1
            | Atom::Jump4
            | Atom::Nop => {}
            _ => shape.tiny_literal_jump = false,
        }
    }
    shape.tiny_literal_jump &= has_jump;
    shape
}

fn print_shape(group: &str, label: &str, atoms: &[Atom]) {
    let s = classify_shape(atoms);
    println!(
        "shape {group}/{label}: linear={}, tiny_lj={}, bytes={}, jumps={}, skips={}, reads={}, control={}, saves={}, checks={}",
        s.linear,
        s.tiny_literal_jump,
        s.bytes,
        s.jumps,
        s.skips,
        s.reads,
        s.control,
        s.saves,
        s.checks,
    );
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
        ParsedPattern::parse("jump4_tiny", "e8 $"),
        ParsedPattern::parse("jump4", "e8 ${'}"),
        ParsedPattern::parse("skip_range", "48 8b [3-10] 48 89"),
        ParsedPattern::parse("alternation", "(85 c0 | 48 85 c0)"),
        ParsedPattern::parse("aligned", "@4 48 8b 2d"),
    ];

    let mut group = c.benchmark_group("scan_pe64");
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    for pat in &patterns {
        print_shape("scan_pe64", pat.label, &pat.atoms);
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
        ParsedPattern::parse("jump4_tiny", "e8 $"),
        ParsedPattern::parse("prologue", "55 41 57 41 56 41 55 41 54 53 48 83"),
        ParsedPattern::parse("jump1", "48 85 c0 74 %'"),
        ParsedPattern::parse("push_pop", "e8 ${41 57} 48"),
        ParsedPattern::parse("alternation", "(85 c0 | 48 85 c0)"),
    ];

    let mut group = c.benchmark_group("scan_elf64");
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    for pat in &patterns {
        print_shape("scan_elf64", pat.label, &pat.atoms);
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
