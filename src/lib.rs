use std::{io::Read, io::Write, path::PathBuf};

use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{self, SignatureConfig};
use pgp::types::KeyTrait;
use pgp::StandaloneSignature;
use rpgpie::key::{checked::CheckedCertificate, component::SignedComponentKeyPub};
use rpgpie_cert_store::Store;
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
        match *self {
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
            Mode::Verify(_) => writeln!(stdout, "\n[GNUPG:] GOODSIG ")?,
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
            Mode::Sign(_) => writeln!(stderr, "\n[GNUPG:] SIG_CREATED ")?,
        }
        Ok(())
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
                .map(hex::encode)
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
        Mode::Sign(_key) => {
            // -- set up card signer
            let card = PcscBackend::cards(None)?.next().unwrap()?;
            let mut card = openpgp_card::Card::new(card)?;
            let mut tx = card.transaction()?;

            let ard = tx.application_related_data()?;
            let ident = ard.application_id()?.ident();
            if let Ok(Some(pin)) = openpgp_card_state::get_pin(&ident) {
                if tx.verify_pw1_sign(pin.as_bytes()).is_err() {
                    // We drop the PIN from the state backend, to avoid exhausting
                    // the retry counter and locking up the User PIN.
                    let res = openpgp_card_state::drop_pin(&ident);

                    if res.is_ok() {
                        writeln!(stderr,
                                            "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! Dropped it from storage.",
                                            &ident)?;
                    } else {
                        writeln!(stderr,
                                            "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! In addition, dropping it from storage failed.",
                                            &ident)?;
                    }
                }
            } else {
                return Err(std::io::Error::other("No signing PIN configured.").into());
            }

            let cs = CardSlot::init_from_card(tx, KeyType::Signing)?;

            // -- use card signer
            let signature = SignatureConfig::new_v4(
                packet::SignatureVersion::V4,
                packet::SignatureType::Binary,
                cs.public_key().algorithm(),
                HashAlgorithm::SHA2_256,
                vec![
                    packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(
                        std::time::SystemTime::now().into(),
                    )),
                    packet::Subpacket::regular(packet::SubpacketData::Issuer(cs.key_id())),
                ],
                vec![],
            );

            let mut buffer = vec![];
            std::io::copy(&mut stdin, &mut buffer)?;
            let signature = signature.sign(&cs, String::new, &buffer[..])?;

            let signature = StandaloneSignature { signature };
            signature.to_armored_writer(&mut stdout, None)?;

            true
        }
    } {
        mode.write_success_trailer(stdout, stderr)?;
        Ok(())
    } else {
        Err(std::io::Error::other("processing error").into())
    }
}
