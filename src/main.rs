use clap::Parser;
use monkeybagel::{run, Args};

fn main() {
    let args = Args::parse();
    if run(
        args,
        std::io::stdin(),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    )
    .is_err()
    {
        std::process::exit(1);
    }
}
