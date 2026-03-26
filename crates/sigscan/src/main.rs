use std::{env, fs, process::ExitCode};

use goblin::Object;
use goblin_lite::{elf, mach, pattern, pe64};
use thiserror::Error;

#[derive(Debug, Error)]
enum CliError {
    #[error("usage: {program} <binary-path> <pattern>")]
    Usage { program: String },
    #[error("invalid pattern syntax")]
    PatternParse {
        #[source]
        source: pattern::ParsePatError,
    },
    #[error("failed to read binary '{path}'")]
    ReadBinary {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to detect binary format for '{path}'")]
    ParseObject {
        path: String,
        #[source]
        source: goblin::error::Error,
    },
    #[error("unsupported binary format for '{path}'")]
    UnsupportedFormat { path: String },
    #[error("ELF scan failed")]
    ElfScan {
        #[source]
        source: elf::ElfError,
    },
    #[error("PE scan failed")]
    PeScan {
        #[source]
        source: pe64::PeError,
    },
    #[error("Mach-O scan failed")]
    MachScan {
        #[source]
        source: mach::MachError,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(matches) => {
            println!("TOTAL matches={matches}");
            if matches == 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            for source in err.sources() {
                eprintln!("  caused by: {source}");
            }
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<usize, CliError> {
    let (path, signature) = parse_args()?;
    let pat = pattern::parse(&signature).map_err(|source| CliError::PatternParse { source })?;
    let bytes = fs::read(&path).map_err(|source| CliError::ReadBinary {
        path: path.clone(),
        source,
    })?;
    let object = Object::parse(&bytes).map_err(|source| CliError::ParseObject {
        path: path.clone(),
        source,
    })?;

    match object {
        Object::Elf(_) => scan_elf(&bytes, &pat),
        Object::PE(_) => scan_pe(&bytes, &pat),
        Object::Mach(_) => scan_mach(&bytes, &pat),
        _ => Err(CliError::UnsupportedFormat { path }),
    }
}

fn parse_args() -> Result<(String, String), CliError> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "sigscan".to_owned());
    let Some(path) = args.next() else {
        return Err(CliError::Usage { program });
    };
    let Some(signature) = args.next() else {
        return Err(CliError::Usage { program });
    };
    if args.next().is_some() {
        return Err(CliError::Usage { program });
    }
    Ok((path, signature))
}

fn scan_elf(bytes: &[u8], pat: &[pattern::Atom]) -> Result<usize, CliError> {
    let file = elf::ElfFile::from_bytes(bytes).map_err(|source| CliError::ElfScan { source })?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), |save| {
        matches.next(save)
    }))
}

fn scan_pe(bytes: &[u8], pat: &[pattern::Atom]) -> Result<usize, CliError> {
    let file = pe64::PeFile::from_bytes(bytes).map_err(|source| CliError::PeScan { source })?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), |save| {
        matches.next(save)
    }))
}

fn scan_mach(bytes: &[u8], pat: &[pattern::Atom]) -> Result<usize, CliError> {
    let file = mach::MachFile::from_bytes(bytes).map_err(|source| CliError::MachScan { source })?;
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

trait ErrorSources {
    fn sources(&self) -> ErrorChain<'_>;
}

impl<E: std::error::Error + ?Sized> ErrorSources for E {
    fn sources(&self) -> ErrorChain<'_> {
        ErrorChain {
            next: self.source(),
        }
    }
}

struct ErrorChain<'a> {
    next: Option<&'a (dyn std::error::Error + 'static)>,
}

impl<'a> Iterator for ErrorChain<'a> {
    type Item = &'a (dyn std::error::Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        self.next = current.source();
        Some(current)
    }
}
