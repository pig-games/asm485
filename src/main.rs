// CLI entrypoint for asm485.
fn main() {
    let use_color = std::env::var("NO_COLOR").is_err();
    match asm485::assembler::run() {
        Ok(reports) => {
            for report in reports {
                for diag in report.diagnostics() {
                    eprintln!(
                        "{}",
                        diag.format_with_context(Some(report.source_lines()), use_color)
                    );
                }
            }
        }
        Err(err) => {
            for diag in err.diagnostics() {
                eprintln!(
                    "{}",
                    diag.format_with_context(Some(err.source_lines()), use_color)
                );
            }
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
