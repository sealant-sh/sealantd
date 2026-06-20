//! sealantd binary entrypoint.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    sealantd::run()
}
