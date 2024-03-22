use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    verify: bool,

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
    Verify,
    Sign(String),
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        if value.verify {
            Ok(Mode::Verify)
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
            Mode::Verify => println!("\n[GNUPG:] GOODSIG "),
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
        Mode::Verify => {}
        Mode::Sign(key) => {}
    }
    mode.write_success_trailer();

    //if email.contains('<') {
    //    email = &email[(email.find('<').unwrap() + 1)..email.find('>').unwrap()];
    //}
    // signature here

    Ok(())
}
