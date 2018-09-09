use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
pub enum Command {
    #[structopt(name = "register", about = "Registers a new user")]
    Register { user: String, pass: String },
    #[structopt(name = "reset-password", about = "Resets a user password")]
    ResetPassword { user: String, pass: String },
}

#[derive(Debug, StructOpt)]
pub struct Options {
    #[structopt(
        short = "r",
        long = "root",
        help = "The path to serve.",
        default_value = ".",
        parse(from_os_str)
    )]
    pub root: PathBuf,
    #[structopt(long = "db", help = "The database path.")]
    pub db: Option<String>,
    #[structopt(
        short = "l",
        long = "listen",
        help = "The address to bind to.",
        default_value = "127.0.0.1"
    )]
    pub address: String,
    #[structopt(
        short = "p",
        long = "port",
        help = "The port to listen on.",
        default_value = "8080"
    )]
    pub port: u16,
    #[structopt(subcommand)]
    pub command: Option<Command>,
}
