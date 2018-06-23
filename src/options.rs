use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
pub struct Options {
    #[structopt(
        short = "r", long = "root", help = "Root path", default_value = ".", parse(from_os_str)
    )]
    pub root: PathBuf,
    #[structopt(
        short = "l", long = "listen", help = "Address to listen on", default_value = "127.0.0.1"
    )]
    pub address: String,
    #[structopt(short = "p", long = "port", help = "Port to bind to", default_value = "8080")]
    pub port: u16,
}
