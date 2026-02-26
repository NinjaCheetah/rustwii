// archive/theme.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the theme building commands in the rustii CLI.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use tempfile::tempdir;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Apply an MYM theme to the Wii Menu
    ApplyMym {
        /// The path to the source MYM file to apply
        mym_path: String,
        /// The path to the base Wii Menu asset archive (000000xx.app)
        base_path: String,
        /// The file to output the finished theme to (<filename>.csm)
        output: String,
    }
}

pub fn theme_apply_mym(mym_path: &str, base_path: &str, output: &str) -> Result<()> {
    todo!();

    Ok(())
}
