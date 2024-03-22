use pgp::types::KeyTrait;
use rpgpie::key::{checked::CheckedCertificate, component::SignedComponentKeyPub};
use rpgpie_cert_store::Store;
use std::{io::Read, io::Write, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug, Default)]
pub struct Args {
    #[clap(long)]
    pub verify: Option<PathBuf>,

    #[clap(long, short = 'b')]
    pub binary: bool,

    #[clap(long, short = 's')]
    pub sign: bool,

    #[clap(long, short = 'a')]
    pub armor: bool,

    #[clap(long, short = 'u')]
    pub user_id: Option<String>,

    #[clap(long)]
    pub keyid_format: Option<String>,

    #[clap(long)]
    pub status_fd: Option<String>,

    pub file_to_verify: Option<String>,
}

enum Mode {
    Verify(PathBuf),
    Sign(String),
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        if let Some(signature) = value.verify {
            Ok(Mode::Verify(signature))
        } else if value.binary && value.sign && value.armor {
            if let Some(user_id) = value.user_id {
                Ok(Mode::Sign(user_id))
            } else {
                Err("Missing user-id value".into())
            }
        } else {
            Err("Unknown mode: only verify and binary, armored sign are supported.".into())
        }
    }
}

impl Mode {
    fn write_success_trailer(
        &self,
        mut stdout: impl Write,
        mut stderr: impl Write,
    ) -> std::io::Result<()> {
        Ok(match *self {
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
            Mode::Verify(_) => writeln!(stdout, "\n[GNUPG:] GOODSIG ")?,
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
            Mode::Sign(_) => writeln!(stderr, "\n[GNUPG:] SIG_CREATED ")?,
        })
    }
}

pub fn run(
    args: Args,
    mut stdin: impl Read,
    mut stdout: impl Write,
    mut stderr: impl Write,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mode: Mode = args.try_into()?;

    if match &mode {
        Mode::Verify(signature) => {
            let store = Store::new()?;
            let mut buffer = vec![];
            std::io::copy(&mut stdin, &mut buffer)?;
            let sig = &rpgpie::sig::load(&mut std::fs::File::open(signature)?)?[0];
            let valid_sigs = sig
                .config
                .issuer_fingerprint()
                .iter()
                .map(|fpr| hex::encode(fpr))
                .map(|fpr| store.search_by_fingerprint(&fpr).ok())
                .flat_map(|certs| {
                    certs
                        .iter()
                        .flatten()
                        .flat_map(|cert| {
                            let key: CheckedCertificate = cert.into();
                            key.valid_signing_capable_component_keys_at(
                                &std::time::SystemTime::now().into(),
                            )
                            .iter()
                            .filter_map(|signing_key| {
                                signing_key
                                    .clone()
                                    .verify(sig, &buffer)
                                    .map(|_| (key.clone(), signing_key.clone(), sig.clone()))
                                    .ok()
                            })
                            .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            for (key, signing_key, _sig) in &valid_sigs {
                writeln!(
                    stderr,
                    "Valid signature from certificate {}",
                    if let SignedComponentKeyPub::Primary((primary, _)) = key.primary_key() {
                        hex::encode(primary.fingerprint())
                    } else {
                        "unknown".into()
                    }
                )?;
                writeln!(
                    stderr,
                    "Valid signature from certificate {}",
                    hex::encode(signing_key.fingerprint())
                )?;
                if let Some(user_id) = key.primary_user_id() {
                    writeln!(stderr, "Valid signature from: {}", user_id.id.id())?;
                }
            }
            //eprintln!("VLD: {valid_sigs:?}");

            if valid_sigs.is_empty() {
                writeln!(stderr, "No valid sigs")?;
                false
            } else {
                true
            }
        }
        Mode::Sign(key) => false,
    } {
        mode.write_success_trailer(stdout, stderr)?;
        Ok(())
    } else {
        Err(std::io::Error::other("processing error").into())
    }
}
