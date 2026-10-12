//! `lc-plugin-host`: runs one LovelyCarve plugin library out of process
//! (`isolation = "process"`) and serves it to LovelyCarve as LPP v1 frames
//! on stdin/stdout.
//!
//! The loader holds no plugin logic. Host requests become plugin calls on
//! worker threads, and the plugin's host calls become LPP requests back to
//! LovelyCarve over the same pipes. LovelyCarve keeps the process in its
//! resource boundary (a Windows Job Object with a memory limit) and kills it
//! to cancel work. Diagnostics go to stderr, which LovelyCarve records as
//! plugin log output; stdout carries protocol frames only.

mod bridge;

use std::{
    ffi::OsString,
    io::{self, BufWriter},
    path::PathBuf,
    process::ExitCode,
};

fn main() -> ExitCode {
    let library = match library_argument(std::env::args_os().skip(1)) {
        Ok(library) => library,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let entry = match lovelycarve_plugin::loader::load_library(&library) {
        Ok(entry) => entry,
        Err(error) => {
            eprintln!("lc-plugin-host: {error}");
            return ExitCode::FAILURE;
        }
    };
    let output = Box::new(BufWriter::with_capacity(64 * 1024, io::stdout()));
    match bridge::serve(entry, io::stdin().lock(), output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lc-plugin-host: {error}");
            ExitCode::FAILURE
        }
    }
}

fn library_argument(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<PathBuf, &'static str> {
    match (arguments.next(), arguments.next(), arguments.next()) {
        (Some(flag), Some(library), None) if flag == "--library" => Ok(PathBuf::from(library)),
        _ => Err("usage: lc-plugin-host --library <plugin library>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_exactly_one_library_argument() {
        let arguments = |items: &[&str]| items.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            library_argument(arguments(&["--library", "a.dll"]).into_iter()),
            Ok(PathBuf::from("a.dll"))
        );
        assert!(library_argument(arguments(&["a.dll"]).into_iter()).is_err());
        assert!(library_argument(arguments(&["--library", "a", "b"]).into_iter()).is_err());
    }
}
