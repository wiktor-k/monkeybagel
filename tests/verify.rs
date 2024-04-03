use std::path::PathBuf;

use monkeybagel::{run, Args};
use rstest::rstest;
use testresult::TestResult;

#[rstest]
fn main(#[files("tests/test-cases/*")] path: PathBuf) -> TestResult {
    let data = std::fs::File::open(path.join("data.txt"))?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let cert_store = testdir::testdir!();

    let cert_d = openpgp_cert_d::CertD::with_base_dir(&cert_store)?;
    for file in std::fs::read_dir(&path)? {
        let path = file?.path();
        if let Some(extension) = path.extension() {
            if extension == "pgp" {
                eprintln!("Inserting new certificate: {}", path.display());
                cert_d.insert_data(&std::fs::read(&path)?, false, |contents, _| {
                    Ok(openpgp_cert_d::MergeResult::DataRef(contents))
                })?;
            }
        }
    }

    drop(cert_d);

    if let Err(e) = run(
        Args {
            verify: Some(path.join("signature.asc")),
            file_to_verify: Some("-".into()),
            cert_store: Some(cert_store),
            ..Default::default()
        },
        data,
        &mut stdout,
        &mut stderr,
    ) {
        eprintln!("An error occurred: {}", e);
        eprintln!("stderr: {}", String::from_utf8_lossy(&stderr));
        println!("stdout: {}", String::from_utf8_lossy(&stdout));
        Err(e.into())
    } else {
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
}
