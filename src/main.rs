// CLI entrypoint for asm485.
fn main() {
    match asm485::assembler::run() {
        Ok(report) => {
            for diag in report.diagnostics() {
                eprintln!("{}", diag.format());
            }
        }
        Err(err) => {
            for diag in err.diagnostics() {
                eprintln!("{}", diag.format());
            }
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
