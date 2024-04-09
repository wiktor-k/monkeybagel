use std::{io::Read, io::Write, path::PathBuf};

use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use openpgp_cert_d::CertD;
use pgp::{ArmorOptions, Deserializable, Signature, SignedSecretKey, StandaloneSignature};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{self, SignatureConfig};
use pgp::types::{KeyTrait, KeyVersion, SecretKeyTrait};
use rpgpie::key::{checked::CheckedCertificate, component::SignedComponentKeyPub};
use rpgpie_certificate_store::Store;

#[derive(Parser, Debug, Default)]
pub struct Args {
    #[clap(long)]
    pub verify: Option<PathBuf>,

    #[clap(long, short = 'b')]
    pub detach_sign: bool,

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

    /// Certificate store. By default uses user's shared PGP certificate directory.
    #[clap(short, long, env = "PGP_CERT_D")]
    pub cert_store: Option<PathBuf>,
}

enum Armor {
    NoArmor,
    Armor,
}

enum Mode {
    Verify {
        signature: PathBuf,
        cert_store: Option<PathBuf>,
    },
    Sign(String, Armor),
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        if let Some(signature) = value.verify {
            if Some("-".into()) == value.file_to_verify {
                Ok(Mode::Verify {
                    signature,
                    cert_store: value.cert_store,
                })
            } else {
                Err("Verification of other files than stdin is unsupported. Use -".into())
            }
        } else if value.detach_sign {
            if let Some(user_id) = value.user_id {
                Ok(Mode::Sign(
                    user_id,
                    if value.armor {
                        Armor::Armor
                    } else {
                        Armor::NoArmor
                    },
                ))
            } else {
                Err("-u parameter is required. Please use hex-encoded signing subkey with no spaces".into())
            }
        } else if value.sign {
            Err("Inline sign is not supported. Use --detach-sign".into())
        } else {
            Err("Unknown mode: only verify and detach-sign operations are supported.".into())
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
            Mode::Verify { .. } => writeln!(stdout, "\n[GNUPG:] GOODSIG ")?,
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
            Mode::Sign(_, _) => writeln!(stderr, "\n[GNUPG:] SIG_CREATED ")?,
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
        Mode::Verify {
            signature,
            cert_store,
        } => {
            let store = if let Some(cert_store) = cert_store {
                Store::with_base_dir(cert_store)?
            } else {
                Store::new()?
            };
            let mut buffer = vec![];
            std::io::copy(&mut stdin, &mut buffer)?;
            let sig = &rpgpie::sig::load(&mut std::fs::File::open(signature)?)?[0];
            //capture sigs:
            //std::fs::copy(signature, "/tmp/data.sig")?;
            //std::fs::File::create_new("/tmp/data")?.write_all(&buffer)?;
            let fingerprints = sig.config.issuer_fingerprint();
            let fingerprints = fingerprints.iter().map(hex::encode).collect::<Vec<_>>();
            let mut certs = fingerprints
                .iter()
                .flat_map(|fpr| store.search_by_fingerprint(fpr).ok())
                .flatten()
                .collect::<Vec<_>>();
            if certs.is_empty() {
                let store = if let Some(cert_store) = cert_store {
                    CertD::with_base_dir(cert_store)?
                } else {
                    CertD::new()?
                };
                for fingerprint in fingerprints {
                    eprintln!("https://keys.openpgp.org/pks/lookup?op=get&options=mr&search={fingerprint}");
                    if let Ok(response) = reqwest::blocking::get(format!("https://keys.openpgp.org/pks/lookup?op=get&options=mr&search={fingerprint}")) {
                        if let Ok(text) = response.text() {
                            if let Ok(loaded_certs) = rpgpie::key::Certificate::load(&mut std::io::Cursor::new(text.as_bytes())) {
                                for cert in loaded_certs {
                                    let mut w = vec![];
                                    rpgpie::key::Certificate::save(&vec![cert.clone()], false, &mut w)?;
                                store.insert_data(&w, false, |old, _new| {
                                    Ok(openpgp_cert_d::MergeResult::DataRef(old))
                                })?;
                                certs.push(cert);
                                    }
                                }
                            }
                        }
                }
            }
            let valid_sigs = certs
                .iter()
                .flat_map(|cert| {
                    let key: CheckedCertificate = cert.into();
                    key.valid_signing_capable_component_keys_at(
                        &std::time::SystemTime::now().into(),
                    )
                    .into_iter()
                    .filter_map(|verifier| {
                        verifier
                            .verify(sig, &buffer)
                            .map(|_| (key.clone(), verifier, sig.clone()))
                            .ok()
                    })
                    .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            for (key, verifier, _sig) in &valid_sigs {
                if let Some(user_id) = key.primary_user_id() {
                    writeln!(stderr, "Signed by: {}", user_id.id.id())?;
                }
                writeln!(
                    stderr,
                    "Certificate: {}",
                    if let SignedComponentKeyPub::Primary((primary, _)) = key.primary_key() {
                        hex::encode(primary.fingerprint())
                    } else {
                        "unknown".into()
                    }
                )?;
                writeln!(
                    stderr,
                    "Signing key: {}",
                    hex::encode(verifier.as_componentkey().fingerprint())
                )?;
            }
            //eprintln!("VLD: {valid_sigs:?}");

            if valid_sigs.is_empty() {
                writeln!(
                    stderr,
                    "No valid sigs for signing key {}",
                    sig.config
                        .issuer_fingerprint()
                        .iter()
                        .map(hex::encode)
                        .fold(String::new(), |a, b| a + " " + &b)
                )?;
                false
            } else {
                true
            }
        }
        Mode::Sign(key, armor) => {
            let signature = if let Some(file_name) = key.strip_prefix("file::") {
                let signer = SignedSecretKey::from_bytes(std::fs::File::open(file_name)?)?;
                complete_signing(signer, stdin)?
            } else {
                let signing_key = if let Some(hex_fpr) = key.strip_prefix("0x") {
                    hex::decode(hex_fpr)?
                } else {
                    hex::decode(key)?
                };
                let mut signature = None;
                for card in PcscBackend::cards(None)? {
                    let card = card?;
                    let mut card = openpgp_card::Card::new(card)?;
                    let mut tx = card.transaction()?;
                    let ard = tx.card().application_related_data()?;
                    let fprs = ard.fingerprints()?;
                    if let Some(fpr) = fprs.signature() {
                        if fpr.as_bytes() == signing_key {
                            let ident = ard.application_id()?.ident();
                            if let Ok(Some(pin)) = openpgp_card_state::get_pin(&ident) {
                                if tx.card().verify_pw1_sign(pin.as_bytes()).is_err() {
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
                                return Err(
                                    std::io::Error::other("No signing PIN configured.").into()
                                );
                            }

                            let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {
                                eprintln!("touch confirmation required")
                            })?;

                            signature = Some(complete_signing(cs, stdin)?);
                            break;
                        }
                    }
                }

                signature.unwrap_or_else(|| {
                    panic!(
                        "No cards attached provide signing for selected key {:?}.",
                        key
                    )
                })
            };
            match armor {
                Armor::Armor => StandaloneSignature { signature }
                    .to_armored_writer(&mut stdout, ArmorOptions::default())?,
                Armor::NoArmor => pgp::packet::write_packet(&mut stdout, &signature)?,
            }
            true
        }
    } {
        mode.write_success_trailer(stdout, stderr)?;
        Ok(())
    } else {
        Err(std::io::Error::other("processing error").into())
    }
}

fn complete_signing(
    signer: impl SecretKeyTrait,
    stdin: impl Read,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let signature = SignatureConfig::new_v4(
        packet::SignatureVersion::V4,
        packet::SignatureType::Binary,
        signer.algorithm(),
        HashAlgorithm::SHA2_256,
        vec![
            packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            packet::Subpacket::regular(packet::SubpacketData::Issuer(signer.key_id())),
            packet::Subpacket::regular(packet::SubpacketData::IssuerFingerprint(
                KeyVersion::V4,
                signer.fingerprint().into(),
            )),
        ],
        vec![],
    );

    let mut hasher = HashAlgorithm::SHA2_256.new_hasher()?;

    signature.hash_data_to_sign(&mut *hasher, stdin)?;
    let len = signature.hash_signature_data(&mut *hasher)?;
    hasher.update(&signature.trailer(len)?);

    let hash = &hasher.finish()[..];

    let signed_hash_value = [hash[0], hash[1]];
    let raw_sig = signer.create_signature(String::new, HashAlgorithm::SHA2_256, hash)?;

    let signature = Signature::from_config(signature, signed_hash_value, raw_sig);

    Ok(signature)
}
