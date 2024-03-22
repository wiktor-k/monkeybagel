use pgp::types::KeyTrait;
use rpgpie::key::{
    checked::CheckedCertificate,
    component::{SignedComponentKey, SignedComponentKeyPub},
};
use rpgpie_cert_store::Store;
use std::{any::Any, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    verify: Option<PathBuf>,

    #[clap(long, short = 'b')]
    binary: bool,

    #[clap(long, short = 's')]
    sign: bool,

    #[clap(long, short = 'a')]
    armor: bool,

    #[clap(long, short = 'u')]
    user_id: Option<String>,

    #[clap(long)]
    keyid_format: Option<String>,

    #[clap(long)]
    status_fd: Option<String>,

    file_to_verify: Option<String>,
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
    fn write_success_trailer(&self) {
        match *self {
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
            Mode::Verify(_) => println!("\n[GNUPG:] GOODSIG "),
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
            Mode::Sign(_) => eprintln!("\n[GNUPG:] SIG_CREATED "),
        }
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    //println!("args: {:?}", args);
    let mode: Mode = args.try_into()?;

    if match &mode {
        Mode::Verify(signature) => {
            let store = Store::new().expect("FIXME");
            let mut buffer = vec![];
            std::io::copy(&mut std::io::stdin(), &mut buffer)?;
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
                eprintln!(
                    "Valid signature from certificate {}",
                    if let SignedComponentKeyPub::Primary((primary, _)) = key.primary_key() {
                        hex::encode(primary.fingerprint())
                    } else {
                        "unknown".into()
                    }
                );
                eprintln!(
                    "Valid signature from certificate {}",
                    hex::encode(signing_key.fingerprint())
                );
                if let Some(user_id) = key.primary_user_id() {
                    eprintln!("Valid signature from: {}", user_id.id.id());
                }
            }
            //eprintln!("VLD: {valid_sigs:?}");

            if valid_sigs.is_empty() {
                eprintln!("No valid sigs");
                false
            } else {
                true
            }
        }
        Mode::Sign(key) => false,
    } {
        mode.write_success_trailer();
    } else {
        std::process::exit(1);
    }

    //if email.contains('<') {
    //    email = &email[(email.find('<').unwrap() + 1)..email.find('>').unwrap()];
    //}
    // signature here

    Ok(())
}
