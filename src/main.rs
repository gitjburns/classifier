use std::process::ExitCode;

// Keeps the scaffold explicitly non-operational until startup is implemented.
fn main() -> ExitCode {
    eprintln!("classifier is not yet configured");
    ExitCode::FAILURE
}
