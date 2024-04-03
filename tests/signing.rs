use monkeybagel::{run, Args};
use pgp::SignedPublicKey;
use pgp::{Deserializable, StandaloneSignature};
use testresult::TestResult;

#[test]
fn signing_key() -> TestResult {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let cert_store = testdir::testdir!();
    let data = "test";
    if let Err(e) = run(
        Args {
            user_id: Some("file::tests/signing-key.pgp".into()),
            sign: true,
            detach_sign: true,
            armor: true,
            cert_store: Some(cert_store),
            ..Default::default()
        },
        data.as_bytes(),
        &mut stdout,
        &mut stderr,
    ) {
        eprintln!("An error occurred: {}", e);
        eprintln!("stderr: {}", String::from_utf8_lossy(&stderr));
        println!("stdout: {}", String::from_utf8_lossy(&stdout));
        Err(e.into())
    } else {
        let verification_key =
            SignedPublicKey::from_bytes(std::fs::File::open("tests/signing-key.pub.pgp")?)?;
        let signature = StandaloneSignature::from_armor_single(std::io::Cursor::new(stdout))?.0;
        signature
            .signature
            .verify(&verification_key, data.as_bytes())?;
        Ok(())
    }
}
