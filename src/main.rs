use rpgpie::key::checked::CheckedCertificate;
use std::path::PathBuf;

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
    eprintln!("Args: {:#?}", args);
    let mode: Mode = args.try_into()?;
    match &mode {
        Mode::Verify(signature) => {
            let mut buffer = vec![];
            std::io::copy(&mut std::io::stdin(), &mut buffer)?;
            let sig = &rpgpie::sig::load(&mut std::fs::File::open(signature)?)?[0];
            let key: CheckedCertificate =
                (&rpgpie::key::Certificate::load(&mut std::fs::File::open("key.asc")?)?[0]).into();
            let valid_sigs: Vec<_> = key
                .valid_signing_capable_component_keys_at(&std::time::SystemTime::now().into())
                .iter()
                .filter_map(|signing_key| signing_key.verify(sig, &buffer).map(|_| sig).ok())
                .collect();

            if valid_sigs.is_empty() {
                println!("no valid signatures");
            } else {
                println!("yep, sigs valid: {valid_sigs:?}");
            }
        }
        Mode::Sign(key) => {}
    }
    mode.write_success_trailer();

    //if email.contains('<') {
    //    email = &email[(email.find('<').unwrap() + 1)..email.find('>').unwrap()];
    //}
    // signature here

    Ok(())
}
