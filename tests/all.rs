use std::path::PathBuf;

use monkeybagel::{run, Args};
use rstest::rstest;
use testresult::TestResult;

#[rstest]
#[ignore]
fn main(#[files("tests/test-cases/*")] path: PathBuf) -> TestResult {
    let data = std::fs::File::open(path.join("data.txt"))?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    run(
        Args {
            verify: Some(path.join("signature.asc")),
            ..Default::default()
        },
        data,
        &mut stdout,
        &mut stderr,
    )?;
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        std::fs::read_to_string(path.join("stdout"))?,
        "stdouts must be equal"
    );
    assert_eq!(
        String::from_utf8_lossy(&stderr),
        std::fs::read_to_string(path.join("stderr"))?,
        "stderrs must be equal"
    );
    Ok(())
}
