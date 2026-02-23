// title/shared.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code shared between title commands in the rustii CLI.

use anyhow::bail;
use clap::Args;
use hex::FromHex;
use regex::RegexBuilder;
use rustwii::title::tmd;

#[derive(Args)]
#[clap(next_help_heading = "Content Identifier")]
#[group(multiple = false, required = true)]
/// Method of identifying individual content in a title, shared between the WAD and TMD commands.
pub struct ContentIdentifier {
    /// The index of the target content
    #[arg(short, long)]
    pub index: Option<usize>,
    /// The Content ID of the target content
    #[arg(short, long)]
    pub cid: Option<String>,
}

#[derive(Args)]
#[clap(next_help_heading = "Possible Modifications")]
#[group(multiple = true, required = true)]
/// Modifications that can be made to a title, shared between the WAD and TMD commands.
pub struct TitleModifications {
    /// A new IOS version for this title (formatted as the decimal IOS version, e.g. 58, with a
    /// valid range of 3-255)
    #[arg(long)]
    pub ios: Option<u8>,
    /// A new Title ID for this title (formatted as 4 ASCII characters, e.g. HADE)
    #[arg(long)]
    pub tid: Option<String>,
    /// A new type for this title (valid options are "System", "Channel", "SystemChannel",
    /// "GameChannel", "DLC", "HiddenChannel")
    #[arg(long)]
    pub r#type: Option<String>,
}

/// Validates a target IOS number and returns its TID.
pub fn validate_target_ios(new_ios: u8) -> Result<[u8; 8], anyhow::Error> {
    if new_ios < 3 {
        bail!("The specified IOS version is not valid! The new IOS version must be between 3 and 255.")
    }
    let new_ios_tid = <[u8; 8]>::from_hex(format!("00000001{:08X}", new_ios))?;
    Ok(new_ios_tid)
}

/// Validates a target Title ID and returns it as a vector.
pub fn validate_target_tid(new_tid_low: &str) -> Result<Vec<u8>, anyhow::Error> {
    let re = RegexBuilder::new(r"^[a-z0-9!@#$%^&*]{4}$").case_insensitive(true).build()?;
    if !re.is_match(new_tid_low) {
        bail!("The specified Title ID is not valid! The new Title ID must be 4 characters and include only letters, numbers, and the special characters \"!@#$%&*\".");
    }
    Ok(Vec::from_hex(hex::encode(new_tid_low))?)
}

/// Validates a target title type and returns it.
pub fn validate_target_type(new_type: &str) -> Result<tmd::TitleType, anyhow::Error> {
    let new_type = match new_type {
        "system" => tmd::TitleType::System,
        "channel" => tmd::TitleType::Channel,
        "systemchannel" => tmd::TitleType::SystemChannel,
        "gamechannel" => tmd::TitleType::GameChannel,
        "dlc" => tmd::TitleType::DLC,
        "hiddenchannel" => tmd::TitleType::HiddenChannel,
        _ => bail!("The specified title type \"{}\" is invalid! Try --help to see valid types.", new_type),
    };
    Ok(new_type)
}
