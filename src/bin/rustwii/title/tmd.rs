// title/tmd.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for TMD-related commands in the rustwii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use hex::FromHex;
use rustwii::title::tmd;
use crate::title::shared::{validate_target_ios, validate_target_tid, validate_target_type, ContentIdentifier, TitleModifications};

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Edit the properties of a TMD file
    Edit {
        /// The path to the TMD to modify
        input: String,
        /// An optional output path; defaults to overwriting input TMD file
        #[arg(short, long)]
        output: Option<String>,
        #[command(flatten)]
        edits: TitleModifications
    },
    /// Remove content from a TMD file
    Remove {
        /// The path to the WAD file to modify
        input: String,
        /// An optional output path; defaults to overwriting input TMD file
        #[arg(short, long)]
        output: Option<String>,
        #[command(flatten)]
        identifier: ContentIdentifier,
    },
}

pub fn tmd_edit(input: &str, output: &Option<String>, edits: &TitleModifications) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source TMD \"{}\" does not exist.", in_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap())
    } else {
        in_path.to_path_buf()
    };

    let mut tmd = tmd::TMD::from_bytes(&fs::read(in_path)?).with_context(|| "The provided TMD file could not be parsed, and is likely invalid.")?;
    // Parse possible edits and perform each one provided.
    let mut changes_summary: Vec<String> = Vec::new();
    // These are joined, because that way if both are selected we only need to set the TID a
    // single time.
    if edits.tid.is_some() || edits.r#type.is_some() {
        let tid_high = if let Some(new_type) = &edits.r#type {
            let new_type = validate_target_type(&new_type.to_ascii_lowercase())?;
            changes_summary.push(format!("Changed title type from \"{}\" to \"{}\"", tmd.title_type()?, new_type));
            Vec::from_hex(format!("{:08X}", new_type as u32))?
        } else {
            tmd.title_id()[0..4].to_vec()
        };

        let tid_low = if let Some(new_tid) = &edits.tid {
            let new_tid = validate_target_tid(&new_tid.to_ascii_uppercase())?;
            changes_summary.push(format!("Changed Title ID from \"{}\" to \"{}\"", hex::encode(&tmd.title_id()[4..8]).to_ascii_uppercase(), hex::encode(&new_tid).to_ascii_uppercase()));
            new_tid
        } else {
            tmd.title_id()[4..8].to_vec()
        };

        let new_tid: Vec<u8> = tid_high.iter().chain(&tid_low).copied().collect();
        tmd.set_title_id(new_tid.try_into().unwrap());
    }

    // Apply IOS edits.
    if let Some(new_ios) = edits.ios {
        let new_ios_tid = validate_target_ios(new_ios)?;
        changes_summary.push(format!("Changed required IOS from IOS{} to IOS{}", tmd.ios_tid().last().unwrap(), new_ios));
        tmd.set_ios_tid(new_ios_tid)?;
    }

    tmd.fakesign()?;
    fs::write(&out_path, tmd.to_bytes()?).with_context(|| format!("Could not open output file \"{}\" for writing.", out_path.display()))?;
    println!("Successfully edited TMD file \"{}\"!\nSummary of changes:", out_path.display());
    for change in &changes_summary {
        println!(" - {}", change);
    }

    Ok(())
}

pub fn tmd_remove(input: &str, output: &Option<String>, identifier: &ContentIdentifier) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source TMD \"{}\" could not be found.", in_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap())
    } else {
        in_path.to_path_buf()
    };
    let mut tmd = tmd::TMD::from_bytes(&fs::read(in_path)?).with_context(|| "The provided TMD file could not be parsed, and is likely invalid.")?;
    // Parse the identifier passed to choose how to find and remove the target.
    // ...maybe don't take the above comment out of context
    if let Some(index) = identifier.index {
        let mut content_records = tmd.content_records().clone();
        content_records.remove(index);
        tmd.set_content_records(&content_records);
        tmd.fakesign().with_context(|| "An unknown error occurred while fakesigning the modified TMD.")?;
        fs::write(&out_path, tmd.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
        println!("Successfully removed content at index {} in TMD file \"{}\".", index, out_path.display());
    } else if identifier.cid.is_some() {
        let cid = u32::from_str_radix(identifier.cid.clone().unwrap().as_str(), 16).with_context(|| "The specified Content ID is invalid!")?;
        let index = match tmd.content_records().iter()
            .find(|record| record.content_id == cid)
            .map(|record| record.index)
        {
            Some(index) => index,
            None => bail!("The specified Content ID \"{}\" ({}) does not exist in this WAD!", identifier.cid.clone().unwrap(), cid),
        };
        let mut content_records = tmd.content_records().clone();
        content_records.remove(index as usize);
        tmd.set_content_records(&content_records);
        tmd.fakesign().with_context(|| "An unknown error occurred while fakesigning the modified TMD.")?;
        fs::write(&out_path, tmd.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
        println!("Successfully removed content with Content ID \"{}\" ({}) in WAD file \"{}\".", identifier.cid.clone().unwrap(), cid, out_path.display());
    }
    Ok(())
}
