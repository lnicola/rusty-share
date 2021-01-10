use pico_args::Arguments;
use std::convert::Infallible;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Command {
    Register {
        user: String,
        pass: String,
        db_path: PathBuf,
    },
    ResetPassword {
        user: String,
        pass: String,
        db_path: PathBuf,
    },
    CreateShare {
        name: String,
        path: PathBuf,
        db_path: PathBuf,
    },
    Start {
        root: PathBuf,
        db_path: Option<PathBuf>,
        address: String,
        port: u16,
    },
    Help,
}

#[derive(Debug)]
pub struct Args {
    pub command: Command,
}

impl Args {
    pub fn parse() -> Result<Self, pico_args::Error> {
        let mut matches = Arguments::from_env();
        let cmd = match matches.subcommand()? {
            Some(cmd) => cmd,
            None => {
                if matches.contains(["-h", "--help"]) {
                    let remaining = matches.finish();
                    if !remaining.is_empty() {
                        eprintln!("Unused arguments: {:?}", remaining);
                    }
                    print_help();
                    return Ok(Args {
                        command: Command::Help,
                    });
                }
                String::from("start")
            }
        };
        match cmd.as_str() {
            "start" => {
                if matches.contains(["-h", "--help"]) {
                    let remaining = matches.finish();
                    if !remaining.is_empty() {
                        eprintln!("Unused arguments: {:?}", remaining);
                    }
                    print_help_start();
                    return Ok(Args {
                        command: Command::Help,
                    });
                }
                let root = matches
                    .opt_value_from_os_str::<_, _, Infallible>(["-r", "--root"], |s| {
                        Ok(PathBuf::from(s))
                    })?
                    .unwrap_or_else(|| PathBuf::from("."));
                let db_path = matches
                    .opt_value_from_os_str::<_, _, Infallible>("--db", |s| Ok(PathBuf::from(s)))?;
                let address = matches
                    .opt_value_from_str(["-l", "--listen"])?
                    .unwrap_or_else(|| String::from("127.0.0.1"));
                let port = matches
                    .opt_value_from_str(["-p", "--port"])?
                    .unwrap_or(8080);
                let remaining = matches.finish();
                if !remaining.is_empty() {
                    eprintln!("Unused arguments: {:?}", remaining);
                }
                Ok(Args {
                    command: Command::Start {
                        root,
                        db_path,
                        address,
                        port,
                    },
                })
            }
            "register" => {
                if matches.contains(["-h", "--help"]) {
                    let remaining = matches.finish();
                    if !remaining.is_empty() {
                        eprintln!("Unused arguments: {:?}", remaining);
                    }
                    print_help_register();
                    return Ok(Args {
                        command: Command::Help,
                    });
                }
                let db_path = matches
                    .value_from_os_str::<_, _, Infallible>("--db", |s| Ok(PathBuf::from(s)))?;
                let user = matches.free_from_str()?;
                let pass = matches.free_from_str()?;
                let remaining = matches.finish();
                if !remaining.is_empty() {
                    eprintln!("Unused arguments: {:?}", remaining);
                }
                Ok(Args {
                    command: Command::Register {
                        user,
                        pass,
                        db_path,
                    },
                })
            }
            "reset-password" => {
                if matches.contains(["-h", "--help"]) {
                    let remaining = matches.finish();
                    if !remaining.is_empty() {
                        eprintln!("Unused arguments: {:?}", remaining);
                    }
                    print_help_reset_password();
                    return Ok(Args {
                        command: Command::Help,
                    });
                }
                let db_path = matches
                    .value_from_os_str::<_, _, Infallible>("--db", |s| Ok(PathBuf::from(s)))?;
                let user = matches.free_from_str()?;
                let pass = matches.free_from_str()?;
                let remaining = matches.finish();
                if !remaining.is_empty() {
                    eprintln!("Unused arguments: {:?}", remaining);
                }
                Ok(Args {
                    command: Command::ResetPassword {
                        user,
                        pass,
                        db_path,
                    },
                })
            }
            "create-share" => {
                if matches.contains(["-h", "--help"]) {
                    let remaining = matches.finish();
                    if !remaining.is_empty() {
                        eprintln!("Unused arguments: {:?}", remaining);
                    }
                    print_help_create_share();
                    return Ok(Args {
                        command: Command::Help,
                    });
                }
                let db_path = matches
                    .value_from_os_str::<_, _, Infallible>("--db", |s| Ok(PathBuf::from(s)))?;
                let name = matches.free_from_str()?;
                let path = matches.free_from_os_str::<_, Infallible>(|s| Ok(PathBuf::from(s)))?;
                let remaining = matches.finish();
                if !remaining.is_empty() {
                    eprintln!("Unused arguments: {:?}", remaining);
                }
                Ok(Args {
                    command: Command::CreateShare {
                        name,
                        path,
                        db_path,
                    },
                })
            }
            _ => {
                print_help();
                Ok(Args {
                    command: Command::Help,
                })
            }
        }
    }
}

fn print_help() {
    eprintln!(
        "rusty-share

USAGE:
    rusty-share [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    start             Starts the server
    register          Registers a new user
    reset-password    Resets a user password
    create-share      Creates a new share
    help              Prints this message or the help of the given subcommand(s)"
    )
}

fn print_help_start() {
    eprintln!(
        "rusty-share start
Starts the server

USAGE:
    rusty-share start [OPTIONS] <user> <pass>

OPTIONS:
    -l, --listen <address>    The address to bind to [default: 127.0.0.1]
    -p, --port <port>         The port to listen on [default: 8080]
    -r, --root <root>         The path to serve [default: .]
        --db <db>             The database path

ARGS:
    <user>    The user name
    <pass>    The user password"
    )
}

fn print_help_register() {
    eprintln!(
        "rusty-share register
Registers a new user

USAGE:
    rusty-share register [OPTIONS] <user> <pass>

OPTIONS:
        --db <db>             The database path

ARGS:
    <user>    The user name
    <pass>    The user password"
    )
}

fn print_help_reset_password() {
    eprintln!(
        "rusty-share reset-password
Resets the password of a user

USAGE:
    rusty-share reset-password [OPTIONS] <user> <pass>

OPTIONS:
        --db <db>             The database path

ARGS:
    <user>    The user name
    <pass>    The new password"
    )
}

fn print_help_create_share() {
    eprintln!(
        "rusty-share create-share
Creates a new share

USAGE:
    rusty-share create-share [OPTIONS] <name> <path>

OPTIONS:
        --db <db>             The database path

ARGS:
    <name>    The share name
    <path>    The share path"
    )
}
