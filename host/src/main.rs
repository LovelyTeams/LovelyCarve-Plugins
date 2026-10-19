//! `lc-plugin-host`: runs one LovelyCarve plugin library out of process and
//! serves it to LovelyCarve as LPP frames on stdin/stdout.
//!
//! The loader holds no plugin logic ([`lovelycarve_plugin::bridge`] does
//! the work). Host requests become plugin calls on worker threads, and the
//! plugin's host calls become LPP requests back to LovelyCarve over the same
//! pipes. LovelyCarve keeps the process in its resource boundary (a Windows
//! Job Object with a memory limit) and kills it to cancel work. Diagnostics
//! go to stderr, which LovelyCarve records as plugin log output; stdout
//! carries protocol frames only.
//!
//! `lc-plugin-host --describe --library <path>` prints the library's
//! `plugin.hello` (analyzers and record schemas) as JSON instead; the
//! plugin build writes it next to the manifest as `schema.json`.

use std::{
    ffi::OsString,
    io::{self, BufWriter, Write},
    path::PathBuf,
    process::ExitCode,
};

use lovelycarve_plugin::bridge;

#[derive(Debug, PartialEq)]
enum Mode {
    Serve(PathBuf),
    Describe(PathBuf),
}

fn main() -> ExitCode {
    let mode = match parse_arguments(std::env::args_os().skip(1)) {
        Ok(mode) => mode,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let library = match &mode {
        Mode::Serve(library) | Mode::Describe(library) => library,
    };
    let entry = match lovelycarve_plugin::loader::load_library(library) {
        Ok(entry) => entry,
        Err(error) => {
            eprintln!("lc-plugin-host: {error}");
            return ExitCode::FAILURE;
        }
    };
    let outcome = match mode {
        Mode::Describe(_) => describe(entry),
        Mode::Serve(_) => {
            let output = Box::new(BufWriter::with_capacity(64 * 1024, io::stdout()));
            bridge::serve(entry, io::stdin().lock(), output)
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lc-plugin-host: {error}");
            ExitCode::FAILURE
        }
    }
}

fn describe(entry: lovelycarve_plugin::abi::EntryFn) -> io::Result<()> {
    let hello = bridge::describe(entry).map_err(|error| io::Error::other(error.to_string()))?;
    let json = serde_json::to_string_pretty(&hello).map_err(io::Error::other)?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{json}")
}

fn parse_arguments(arguments: impl Iterator<Item = OsString>) -> Result<Mode, &'static str> {
    const USAGE: &str = "usage: lc-plugin-host [--describe] --library <plugin library>";
    let arguments: Vec<OsString> = arguments.collect();
    match arguments.as_slice() {
        [flag, library] if flag == "--library" => Ok(Mode::Serve(PathBuf::from(library))),
        [describe, flag, library] if describe == "--describe" && flag == "--library" => {
            Ok(Mode::Describe(PathBuf::from(library)))
        }
        _ => Err(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_exactly_one_library_argument() {
        let arguments = |items: &[&str]| items.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            parse_arguments(arguments(&["--library", "a.dll"]).into_iter()),
            Ok(Mode::Serve(PathBuf::from("a.dll")))
        );
        assert_eq!(
            parse_arguments(arguments(&["--describe", "--library", "a.dll"]).into_iter()),
            Ok(Mode::Describe(PathBuf::from("a.dll")))
        );
        assert!(parse_arguments(arguments(&["a.dll"]).into_iter()).is_err());
        assert!(parse_arguments(arguments(&["--library", "a", "b"]).into_iter()).is_err());
    }
}
