// nand/setting.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for setting.txt-related commands in the rustwii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use regex::RegexBuilder;
use rustwii::nand::setting::SettingTxt;

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
    },
    /// Generate a new setting.txt from the provided values
    Gen {
        /// The serial number of the console this file is for
        serno: String,
        /// Region of the console this file is for (USA, EUR, JPN, or KOR)
        region: String
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
    let setting = SettingTxt::from_bytes(&fs::read(in_path)?).with_context(|| "The provided setting.txt could not be parsed, and is likely invalid.")?;
    fs::write(out_path, setting.to_string()?)?;

    println!("Successfully decrypted setting.txt!");

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
    let setting = SettingTxt::from_string(String::from_utf8(fs::read(in_path)?).with_context(|| "Invalid characters found in input file!")?)?;
    fs::write(out_path, setting.to_bytes()?)?;

    println!("Successfully encrypted setting.txt!");

    Ok(())
}

pub fn generate_setting(serno: &str, region: &str) -> Result<()> {
    // Validate the provided SN. It should be 2 or 3 letters followed by 9 numbers.
    if serno.len() != 11 && serno.len() != 12 {
        bail!("The provided Serial Number is not valid!")
    }

    let re = RegexBuilder::new(r"[0-9]+").case_insensitive(true).build()?;
    if !re.is_match(&serno[serno.len() - 9..]) {
        bail!("The provided Serial Number is not valid!")
    }

    let prefix = &serno[..serno.len() - 9];

    // Detect the console revision based on the SN.
    let revision = match prefix.chars().next().unwrap() {
        'L' => "RVL-001",
        'K' => "RVL-101",
        'H' => "RVL-201",
        _ => "RVL-001"
    };

    // Validate the region, and then validate the SN based on the region. USA has a two-letter
    // prefix for a total length of 11 characters, while other regions have a three-letter prefix
    // for a total length of 12 characters.
    let valid_regions = ["USA", "EUR", "JPN", "KOR"];
    if !valid_regions.contains(&region) {
        bail!("The provided region \"{region}\" is not valid!")
    }
    if (prefix.len() == 2 && region != "USA") || (prefix.len() == 3 && region == "USA") {
        bail!("The provided region \"{region}\" does not match the provided Serial Number {serno}!")
    }

    // Find the values of VIDEO and GAME.
    let (video, game) = match region {
        "USA" => ("NTSC", "US"),
        "EUR" => ("PAL", "EU"),
        "JPN" => ("NTSC", "JP"),
        "KOR" => ("NTSC", "KR"),
        _ => bail!("The provided region \"{region}\" is not valid!")
    };

    let model = format!("{revision}({region})");
    let serial_number = &serno[serno.len() - 9..];

    let setting_str = format!("\
        AREA={}\r\n\
        MODEL={}\r\n\
        DVD=0\r\n\
        MPCH=0x7FFE\r\n\
        CODE={}\r\n\
        SERNO={}\r\n\
        VIDEO={}\r\n\
        GAME={}\r\n", region, model, prefix, serial_number, video, game
    );
    let setting_txt = SettingTxt::from_string(setting_str)?;
    fs::write("setting.txt", setting_txt.to_bytes()?)
        .with_context(|| "Failed to write setting.txt!")?;

    println!("Successfully created setting.txt for console with serial number {serno} and \
    region {region}!");

    Ok(())
}
