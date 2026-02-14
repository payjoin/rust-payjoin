use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(version)]
pub struct Args {
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}
