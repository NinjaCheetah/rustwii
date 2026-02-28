// nand/setting.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for setting.txt-related commands in the rustwii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use rustwii::nand::setting;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Decrypt setting.txt
    Decrypt {
        /// The path to the setting.txt file to decrypt
        input: String,
        /// An optional output path; defaults to setting_dec.txt
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Encrypt setting.txt
    Encrypt {
        /// The path to the setting.txt to encrypt
        input: String,
        /// An optional output path; defaults to setting_enc.txt
        #[arg(short, long)]
        output: Option<String>,
    }
}

pub fn decrypt_setting(input: &str, output: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source file \"{}\" could not be found.", in_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap()).with_extension("txt")
    } else {
        PathBuf::from("setting_dec.txt")
    };
    let setting = setting::SettingTxt::from_bytes(&fs::read(in_path)?).with_context(|| "The provided setting.txt could not be parsed, and is likely invalid.")?;
    fs::write(out_path, setting.to_string()?)?;
    Ok(())
}

pub fn encrypt_setting(input: &str, output: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source file \"{}\" could not be found.", in_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap()).with_extension("txt")
    } else {
        PathBuf::from("setting_enc.txt")
    };
    let setting = setting::SettingTxt::from_string(String::from_utf8(fs::read(in_path)?).with_context(|| "Invalid characters found in input file!")?)?;
    fs::write(out_path, setting.to_bytes()?)?;
    Ok(())
}
