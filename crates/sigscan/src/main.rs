use std::{env, fs, process::ExitCode};

use goblin::Object;
use goblin_lite::{elf, mach, pattern, pe64};

fn main() -> ExitCode {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "sigscan".to_owned());
    let Some(path) = args.next() else {
        eprintln!("usage: {program} <binary-path> <pattern>");
        return ExitCode::from(2);
    };
    let Some(signature) = args.next() else {
        eprintln!("usage: {program} <binary-path> <pattern>");
        return ExitCode::from(2);
    };

    if args.next().is_some() {
        eprintln!("usage: {program} <binary-path> <pattern>");
        return ExitCode::from(2);
    }

    let pat = match pattern::parse(&signature) {
        Ok(pat) => pat,
        Err(err) => {
            eprintln!("invalid pattern: {err}");
            return ExitCode::from(2);
        }
    };

    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("failed to read {path}: {err}");
            return ExitCode::from(2);
        }
    };

    let object = match Object::parse(&bytes) {
        Ok(object) => object,
        Err(err) => {
            eprintln!("failed to parse binary format for {path}: {err}");
            return ExitCode::from(2);
        }
    };

    let result = match object {
        Object::Elf(_) => scan_elf(&bytes, &pat),
        Object::PE(_) => scan_pe(&bytes, &pat),
        Object::Mach(_) => scan_mach(&bytes, &pat),
        _ => Err(format!("unsupported binary format for {path}")),
    };

    match result {
        Ok(matches) => {
            println!("TOTAL matches={matches}");
            if matches == 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}

fn scan_elf(bytes: &[u8], pat: &[pattern::Atom]) -> Result<usize, String> {
    let file = elf::ElfFile::from_bytes(bytes).map_err(|err| format!("ELF parse error: {err}"))?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), |save| {
        matches.next(save)
    }))
}

fn scan_pe(bytes: &[u8], pat: &[pattern::Atom]) -> Result<usize, String> {
    let file = pe64::PeFile::from_bytes(bytes).map_err(|err| format!("PE parse error: {err}"))?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), |save| {
        matches.next(save)
    }))
}

fn scan_mach(bytes: &[u8], pat: &[pattern::Atom]) -> Result<usize, String> {
    let file =
        mach::MachFile::from_bytes(bytes).map_err(|err| format!("Mach-O parse error: {err}"))?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), |save| {
        matches.next(save)
    }))
}

fn scan_with_next<F>(save_len: usize, mut next_match: F) -> usize
where
    F: FnMut(&mut [u64]) -> bool,
{
    debug_assert!(
        save_len >= 1,
        "pattern parser inserts an implicit Save(0) and always needs at least one slot"
    );
    let mut save = vec![0u64; save_len];
    let mut total = 0usize;

    while next_match(&mut save) {
        total += 1;
        println!(
            "MATCH {total:04} base=0x{:X} save={}",
            save[0],
            format_slots(&save)
        );
    }

    total
}

fn format_slots(save: &[u64]) -> String {
    let mut out = String::from("[");
    for (index, value) in save.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("0x{value:X}"));
    }
    out.push(']');
    out
}
