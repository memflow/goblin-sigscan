use std::{env, fs, process::ExitCode};

use goblin::Object;
use goblin_sigscan::{elf, mach, pattern, pe64};
use thiserror::Error;

/// Parsed command-line arguments.
struct Args {
    path: String,
    signature: String,
    /// Suppress per-match output. Useful when profiling the scan loop (e.g. under
    /// `cargo flamegraph`) so stdout formatting doesn't dominate the profile.
    quiet: bool,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("usage: {program} [--quiet] <binary-path> <pattern>")]
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
    let args = parse_args()?;
    let pat =
        pattern::parse(&args.signature).map_err(|source| CliError::PatternParse { source })?;
    let bytes = fs::read(&args.path).map_err(|source| CliError::ReadBinary {
        path: args.path.clone(),
        source,
    })?;
    let object = Object::parse(&bytes).map_err(|source| CliError::ParseObject {
        path: args.path.clone(),
        source,
    })?;

    match object {
        Object::Elf(_) => scan_elf(&bytes, &pat, args.quiet),
        Object::PE(_) => scan_pe(&bytes, &pat, args.quiet),
        Object::Mach(_) => scan_mach(&bytes, &pat, args.quiet),
        _ => Err(CliError::UnsupportedFormat { path: args.path }),
    }
}

fn parse_args() -> Result<Args, CliError> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "sigscan".to_owned());

    let mut quiet = false;
    let mut positional = Vec::with_capacity(2);
    for arg in args {
        match arg.as_str() {
            "--quiet" | "-q" => quiet = true,
            _ => positional.push(arg),
        }
    }

    let [path, signature] =
        <[String; 2]>::try_from(positional).map_err(|_| CliError::Usage { program })?;
    Ok(Args {
        path,
        signature,
        quiet,
    })
}

fn scan_elf(bytes: &[u8], pat: &[pattern::Atom], quiet: bool) -> Result<usize, CliError> {
    let file = elf::ElfFile::from_bytes(bytes).map_err(|source| CliError::ElfScan { source })?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), quiet, |save| {
        matches.next(save)
    }))
}

fn scan_pe(bytes: &[u8], pat: &[pattern::Atom], quiet: bool) -> Result<usize, CliError> {
    let file = pe64::PeFile::from_bytes(bytes).map_err(|source| CliError::PeScan { source })?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), quiet, |save| {
        matches.next(save)
    }))
}

fn scan_mach(bytes: &[u8], pat: &[pattern::Atom], quiet: bool) -> Result<usize, CliError> {
    let file = mach::MachFile::from_bytes(bytes).map_err(|source| CliError::MachScan { source })?;
    let mut matches = file.scanner().matches_code(pat);
    Ok(scan_with_next(pattern::save_len(pat), quiet, |save| {
        matches.next(save)
    }))
}

fn scan_with_next<F>(save_len: usize, quiet: bool, mut next_match: F) -> usize
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
        if !quiet {
            println!(
                "MATCH {total:04} base=0x{:X} save={}",
                save[0],
                format_slots(&save)
            );
        }
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
