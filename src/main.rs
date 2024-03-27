use clap::Parser;
use monkeybagel::{run, Args};

fn main() {
    let args = Args::parse();
    if let Err(e) = run(
        args,
        std::io::stdin(),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    ) {
        eprintln!("Lieutenant error: {e}");
        std::process::exit(1);
    }
}
