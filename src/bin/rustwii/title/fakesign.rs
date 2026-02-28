// title/fakesign.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the fakesign command in the rustwii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use rustwii::{title, title::tmd, title::ticket};
use crate::filetypes::{WiiFileType, identify_file_type};

pub fn fakesign(input: &str, output: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Input file \"{}\" does not exist.", in_path.display());
    }
    match identify_file_type(input) {
        Some(WiiFileType::Wad) => {
            let out_path = if output.is_some() {
                PathBuf::from(output.clone().unwrap().as_str()).with_extension("wad")
            } else {
                PathBuf::from(input)
            };
            // Load WAD into a Title instance, then fakesign it.
            let mut title = title::Title::from_bytes(fs::read(in_path).with_context(|| "Could not open WAD file for reading.")?.as_slice())
                .with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
            title.fakesign().with_context(|| "An unknown error occurred while fakesigning the provided WAD.")?;
            // Write output file.
            fs::write(out_path, title.to_wad()?.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
            println!("WAD fakesigned!");
        },
        Some(WiiFileType::Tmd) => {
            let out_path = if output.is_some() {
                PathBuf::from(output.clone().unwrap().as_str()).with_extension("tmd")
            } else {
                PathBuf::from(input)
            };
            // Load TMD into a TMD instance, then fakesign it.
            let mut tmd = tmd::TMD::from_bytes(fs::read(in_path).with_context(|| "Could not open TMD file for reading.")?.as_slice())
                .with_context(|| "The provided TMD file could not be parsed, and is likely invalid.")?;
            tmd.fakesign().with_context(|| "An unknown error occurred while fakesigning the provided TMD.")?;
            // Write output file.
            fs::write(out_path, tmd.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
            println!("TMD fakesigned!");
        },
        Some(WiiFileType::Ticket) => {
            let out_path = if output.is_some() {
                PathBuf::from(output.clone().unwrap().as_str()).with_extension("tik")
            } else {
                PathBuf::from(input)
            };
            // Load Ticket into a Ticket instance, then fakesign it.
            let mut ticket = ticket::Ticket::from_bytes(fs::read(in_path).with_context(|| "Could not open Ticket file for reading.")?.as_slice())
                .with_context(|| "The provided Ticket file could not be parsed, and is likely invalid.")?;
            ticket.fakesign().with_context(|| "An unknown error occurred while fakesigning the provided Ticket.")?;
            // Write output file.
            fs::write(out_path, ticket.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
            println!("Ticket fakesigned!");
        },
        _ => {
            bail!("You can only fakesign TMDs, Tickets, and WADs!");
        }
    }
    Ok(())
}
