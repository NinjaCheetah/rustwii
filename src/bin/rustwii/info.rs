// info.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the info command in the rustii CLI.

use std::{str, fs};
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use anyhow::{bail, Context, Result};
use rustwii::archive::u8;
use rustwii::{title, title::cert, title::tmd, title::ticket, title::wad, title::versions};
use crate::filetypes::{WiiFileType, identify_file_type};

// Avoids duplicated code, since both TMD and Ticket info print the TID in the same way.
fn print_tid(title_id: [u8; 8]) -> Result<()> {
    let ascii = String::from_utf8_lossy(&title_id[4..]).trim_end_matches('\0').trim_start_matches('\0').to_owned();
    let ascii_tid = if ascii.len() == 4 {
        Some(ascii)
    } else {
        None
    };
    if let Some(ascii_tid) = ascii_tid {
        println!("  Title ID: {} ({})", hex::encode(title_id).to_uppercase(), ascii_tid);
    } else {
        println!("  Title ID: {}", hex::encode(title_id).to_uppercase());
    }
    Ok(())
}

// Same as above, both the TMD and Ticket info print the title version in the same way.
fn print_title_version(title_version: u16, title_id: [u8; 8], is_vwii: bool) -> Result<()> {
    let converted_ver = versions::dec_to_standard(title_version, &hex::encode(title_id), Some(is_vwii));
    if hex::encode(title_id).eq("0000000100000001") {
        println!("  Title Version: {} (boot2v{})", title_version, title_version);
    } else if hex::encode(title_id)[..8].eq("00000001") && converted_ver.is_some() {
        println!("  Title Version: {} ({})", title_version, converted_ver.unwrap());
    } else {
        println!("  Title Version: {}", title_version);
    }
    Ok(())
}

fn print_tmd_info(tmd: tmd::TMD, cert: Option<cert::Certificate>) -> Result<()> {
    // Print all important keys from the TMD.
    println!("Title Info");
    print_tid(tmd.title_id())?;
    print_title_version(tmd.title_version(), tmd.title_id(), tmd.is_vwii())?;
    println!("  TMD Version: {}", tmd.tmd_version());
    if hex::encode(tmd.ios_tid()).eq("0000000000000000") {
        println!("  Required IOS: N/A");
    }
    else if hex::encode(tmd.ios_tid()).ne(&format!("{:016X}", tmd.title_version())) {
        println!("  Required IOS: IOS{} ({})", tmd.ios_tid().last().unwrap(), hex::encode(tmd.ios_tid()).to_uppercase());
    }
    let signature_issuer = String::from_utf8(Vec::from(tmd.signature_issuer())).unwrap_or_default();
    if signature_issuer.contains("CP00000004") {
        println!("  Certificate: CP00000004 (Retail)");
        println!("  Certificate Issuer: Root-CA00000001 (Retail)");
    }
    else if signature_issuer.contains("CP00000007") {
        println!("  Certificate: CP00000007 (Development)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    }
    else if signature_issuer.contains("CP00000005") {
        println!("  Certificate: CP00000005 (Development/Unknown)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    }
    else if signature_issuer.contains("CP10000000") {
        println!("  Certificate: CP10000000 (Arcade)");
        println!("  Certificate Issuer: Root-CA10000000 (Arcade)");
    }
    else {
        println!("  Certificate Info: {} (Unknown)", signature_issuer);
    }
    let region = if hex::encode(tmd.title_id()).eq("0000000100000002") {
        match versions::dec_to_standard(tmd.title_version(), &hex::encode(tmd.title_id()), Some(tmd.is_vwii()))
            .unwrap_or_default().chars().last() {
            Some('U') => "USA",
            Some('E') => "EUR",
            Some('J') => "JPN",
            Some('K') => "KOR",
            _ => "None"
        }
    } else if matches!(tmd.title_type(), Ok(tmd::TitleType::System)) {
        "None"
    } else {
        tmd.region()
    };
    println!("  Region: {}", region);
    println!("  Title Type: {}", tmd.title_type()?);
    println!("  vWii Title: {}", tmd.is_vwii());
    println!("  DVD Video Access: {}", tmd.check_access_right(tmd::AccessRight::DVDVideo));
    println!("  AHB Access: {}", tmd.check_access_right(tmd::AccessRight::AHB));
    if let Some(cert) = cert {
        let signing_str = match cert::verify_tmd(&cert, &tmd) {
            Ok(result) => match result {
                true => "Valid (Unmodified TMD)",
                false => {
                    if tmd.is_fakesigned() {
                        "Fakesigned"
                    } else {
                        "Invalid (Modified TMD)"
                    }
                },
            },
            Err(_) => {
                if tmd.is_fakesigned() {
                    "Fakesigned"
                } else {
                    "Invalid (Modified TMD)"
                }
            }
        };
        println!("  Signature: {}", signing_str);
    } else {
        println!("  Fakesigned: {}", tmd.is_fakesigned());
    }
    println!("\nContent Info");
    println!("  Total Contents: {}", tmd.content_records().len());
    println!("  Boot Content Index: {}", tmd.boot_index());
    println!("  Content Records:");
    for content in tmd.content_records().iter() {
        println!("    Content Index: {}", content.index);
        println!("      Content ID: {:08X}", content.content_id);
        println!("      Content Type: {}", content.content_type);
        println!("      Content Size: {} bytes ({} blocks)", content.content_size, title::bytes_to_blocks(content.content_size as usize));
        println!("      Content Hash: {}", hex::encode(content.content_hash));
    }
    Ok(())
}

fn print_ticket_info(ticket: ticket::Ticket, cert: Option<cert::Certificate>) -> Result<()> {
    // Print all important keys from the Ticket.
    println!("Ticket Info");
    print_tid(ticket.title_id())?;
    print_title_version(ticket.title_version(), ticket.title_id(), ticket.common_key_index() == 2)?;
    println!("  Ticket Version: {}", ticket.ticket_version());
    let signature_issuer = String::from_utf8(Vec::from(ticket.signature_issuer())).unwrap_or_default();
    if signature_issuer.contains("XS00000003") {
        println!("  Certificate: XS00000003 (Retail)");
        println!("  Certificate Issuer: Root-CA00000001 (Retail)");
    } else if signature_issuer.contains("XS00000006") {
        println!("  Certificate: XS00000006 (Development)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    } else if signature_issuer.contains("XS00000004") {
        println!("  Certificate: XS00000004 (Development/Unknown)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    } else {
        println!("  Certificate Info: {} (Unknown)", signature_issuer);
    }
    let key = match ticket.common_key_index() {
        0 => {
            if ticket.is_dev() { "Common (Development)" }
            else { "Common (Retail)" }
        }
        1 => "Korean",
        2 => "vWii",
        _ => "Unknown (Likely Common)"
    };
    println!("  Decryption Key: {}", key);
    println!("  Title Key (Encrypted): {}", hex::encode(ticket.title_key()));
    println!("  Title Key (Decrypted): {}", hex::encode(ticket.title_key_dec()));
    if let Some(cert) = cert {
        let signing_str = match cert::verify_ticket(&cert, &ticket) {
            Ok(result) => match result {
                true => "Valid (Unmodified Ticket)",
                false => {
                    if ticket.is_fakesigned() {
                        "Fakesigned"
                    } else {
                        "Invalid (Modified Ticket)"
                    }
                },
            },
            Err(_) => {
                if ticket.is_fakesigned() {
                    "Fakesigned"
                } else {
                    "Invalid (Modified Ticket)"
                }
            }
        };
        println!("  Signature: {}", signing_str);
    } else {
        println!("  Fakesigned: {}", ticket.is_fakesigned());
    }
    Ok(())
}

fn print_wad_info(wad: wad::WAD) -> Result<()> {
    println!("WAD Info");
    match wad.wad_type() {
        wad::WADType::ImportBoot => { println!("  WAD Type: boot2") },
        wad::WADType::Installable => { println!("  WAD Type: Standard Installable") },
    }
    // Create a Title for size info, signing info and TMD/Ticket info.
    let title = title::Title::from_wad(&wad).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
    let min_size_blocks = title::bytes_to_blocks(title.title_size(None)?);
    let max_size_blocks = title::bytes_to_blocks(title.title_size(Some(true))?);
    if min_size_blocks == max_size_blocks {
        println!("  Installed Size: {} blocks", min_size_blocks);
    } else {
        println!("  Installed Size: {}-{} blocks", min_size_blocks, max_size_blocks);
    }
    let min_size = title.title_size(None)? as f64 / 1048576.0;
    let max_size = title.title_size(Some(true))? as f64 / 1048576.0;
    if min_size == max_size {
        println!("  Installed Size (MB): {:.2} MB", min_size);
    } else {
        println!("  Installed Size (MB): {:.2}-{:.2} MB", min_size, max_size);
    }
    println!("  Has Meta/Footer: {}", wad.meta_size() != 0);
    println!("  Has CRL: {}", wad.crl_size() != 0);
    let signing_str = match title.verify() {
        Ok(result) => match result {
            true => "Legitimate (Unmodified TMD + Ticket)",
            false => {
                if title.is_fakesigned() {
                    "Fakesigned"
                } else if cert::verify_tmd(&title.cert_chain.tmd_cert(), &title.tmd)? {
                    "Piratelegit (Unmodified TMD, Modified Ticket)"
                } else if  cert::verify_ticket(&title.cert_chain.ticket_cert(), &title.ticket)? {
                    "Edited (Modified TMD, Unmodified Ticket)"
                } else {
                    "Illegitimate (Modified TMD + Ticket)"
                }
            },
        },
        Err(_) => {
            if title.is_fakesigned() {
                "Fakesigned"
            } else {
                "Illegitimate (Modified TMD + Ticket)"
            }
        }
    };
    println!("  Signing Status: {}", signing_str);
    println!();
    print_ticket_info(title.ticket, Some(title.cert_chain.ticket_cert()))?;
    println!();
    print_tmd_info(title.tmd, Some(title.cert_chain.tmd_cert()))?;
    Ok(())
}

fn print_full_tree(dir: &Rc<RefCell<u8::U8Directory>>, indent: usize) {
    let prefix = "  ".repeat(indent);
    let dir_name = if !dir.borrow().name.is_empty() {
        &dir.borrow().name
    } else {
        &String::from("root")
    };
    println!("{}D {}", prefix, dir_name);

    // Print subdirectories
    for subdir in &dir.borrow().dirs {
        print_full_tree(subdir, indent + 1);
    }

    // Print files
    for file in &dir.borrow().files {
        let file_name = &file.borrow().name;
        println!("{}  F {}", prefix, file_name);
    }
}

fn print_u8_info(u8_archive: u8::U8Archive) -> Result<()> {
    println!("U8 Archive Info");
    println!("  Node Count: {}", u8_archive.node_tree.borrow().count());
    println!("  Archive Data:");
    print_full_tree(&u8_archive.node_tree, 2);
    Ok(())
}

pub fn info(input: &str) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Input file \"{}\" does not exist.", in_path.display());
    }
    match identify_file_type(input) {
        Some(WiiFileType::Tmd) => {
            let tmd = tmd::TMD::from_bytes(&fs::read(in_path)?).with_context(|| "The provided TMD file could not be parsed, and is likely invalid.")?;
            print_tmd_info(tmd, None)?;
        },
        Some(WiiFileType::Ticket) => {
            let ticket = ticket::Ticket::from_bytes(&fs::read(in_path)?).with_context(|| "The provided Ticket file could not be parsed, and is likely invalid.")?;
            print_ticket_info(ticket, None)?;
        },
        Some(WiiFileType::Wad) => {
            let wad = wad::WAD::from_bytes(&fs::read(in_path)?).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
            print_wad_info(wad)?;
        },
        Some(WiiFileType::U8) => {
            let u8_archive = u8::U8Archive::from_bytes(&fs::read(in_path)?).with_context(|| "The provided U8 archive could not be parsed, and is likely invalid.")?;
            print_u8_info(u8_archive)?;
        }
        None => {
            bail!("Information cannot be displayed for this file type.");
        }
    }
    Ok(())
}
