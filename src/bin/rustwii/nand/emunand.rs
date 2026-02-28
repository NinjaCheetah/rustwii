// nand/emunand.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for EmuNAND-related commands in the rustwii CLI.

use std::{str, fs};
use std::path::{absolute, Path};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use walkdir::WalkDir;
use rustwii::nand::{emunand, setting};
use rustwii::title::{nus, tmd};
use rustwii::title;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Display information about an EmuNAND
    Info {
        emunand: String,
    },
    /// Automatically install missing IOSes to an EmuNAND
    InstallMissing {
        /// The path to the target EmuNAND
        emunand: String,
        /// Explicitly install vWii IOSes instead of detecting the EmuNAND type automatically
        #[clap(long)]
        vwii: bool
    },
    /// Install a WAD file to an EmuNAND
    InstallTitle {
        /// The path to the WAD file to install
        wad: String,
        /// The path to the target EmuNAND
        emunand: String,
        /// Install the content at index 0 as title.met; this will override any meta/footer data
        /// included in the WAD
        #[clap(long)]
        override_meta: bool,
    },
    /// Uninstall a title from an EmuNAND
    UninstallTitle {
        /// The Title ID of the title to uninstall, or the path to a WAD file to read the Title ID
        /// from
        tid: String,
        /// The path to the target EmuNAND
        emunand: String,
        /// Remove the Ticket file; default behavior is to leave it intact
        #[clap(long)]
        remove_ticket: bool,
    }
}

pub fn info(emunand: &str) -> Result<()> {
    let emunand_path = Path::new(emunand);
    if !emunand_path.exists() {
        bail!("Target EmuNAND directory \"{}\" could not be found.", emunand_path.display());
    }
    let emunand = emunand::EmuNAND::open(emunand_path.to_path_buf())?;
    // Summarize all the details of an EmuNAND.
    println!("EmuNAND Info");
    println!("  Path: {}", absolute(emunand_path)?.display());
    let mut is_vwii = false;
    match emunand.get_title_tmd([0, 0, 0, 1, 0, 0, 0, 2]) {
        Some(tmd) => {
            is_vwii = tmd.is_vwii();
            println!("  System Menu Version: {}", title::versions::dec_to_standard(tmd.title_version(), "0000000100000002", Some(is_vwii)).unwrap());
        },
        None => {
            println!("  System Menu Version: None");
        }
    }
    let setting_path = emunand.get_emunand_dir("title").unwrap()
        .join("00000001")
        .join("00000002")
        .join("data")
        .join("setting.txt");
    if setting_path.exists() {
        let setting_txt = setting::SettingTxt::from_bytes(&fs::read(setting_path)?)?;
        println!("  System Region: {}", setting_txt.area);
    } else {
        println!("  System Region: N/A");
    }
    if is_vwii {
        println!("  Type: vWii");
    } else {
        println!("  Type: Wii");
    }
    let categories = emunand.get_installed_titles();
    let mut installed_count = 0;
    for category in &categories {
        if category.title_type != "00010000" {
            for _ in &category.titles {
                installed_count += 1;
            }
        }
    }
    println!("  Installed Titles: {}", installed_count);
    let total_size: u64 = WalkDir::new(emunand.get_emunand_dir("root").unwrap())
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| fs::metadata(entry.path()).map(|m| m.len()).unwrap_or(0))
        .sum();
    println!("  Space Used: {} blocks ({:.2} MB)", title::bytes_to_blocks(total_size as usize), total_size as f64 / 1048576.0);
    println!();
    // Build a catalog of all installed titles so that we can display them.
    let mut installed_ioses: Vec<String> = Vec::new();
    let mut installed_titles: Vec<String> = Vec::new();
    let mut disc_titles: Vec<String> = Vec::new();
    for category in categories {
        if category.title_type == "00000001" {
            let mut ioses: Vec<u32> = Vec::new();
            for title in category.titles {
                if title != "00000002" {
                    ioses.push(u32::from_str_radix(&title, 16)?);
                }
            }
            ioses.sort();
            ioses.iter().for_each(|x| installed_ioses.push(format!("00000001{:08X}", x)));
        } else if category.title_type != "00010000" {
            category.titles.iter().for_each(|x| installed_titles.push(format!("{}{}", category.title_type, x).to_ascii_uppercase()));
        } else if category.title_type == "00000000" {
            category.titles.iter().filter(|x| x.as_str() != "48415A41")
                .for_each(|x| disc_titles.push(format!("{}{}", category.title_type, x).to_ascii_uppercase()));
        }
    }
    // Print the titles that are installed to the EmuNAND.
    if !installed_ioses.is_empty() {
        println!("System Titles:");
        for ios in &installed_ioses {
            if ["00000001", "00000100", "00000101", "00000200", "00000201"].contains(&&ios[8..16]) {
                if ios[8..16].eq("00000001") {
                    println!("  boot2 ({})", ios.to_ascii_uppercase());
                } else if ios[8..16].eq("00000100") {
                    println!("  BC ({})", ios.to_ascii_uppercase());
                } else if ios[8..16].eq("00000101") {
                    println!("  MIOS ({})", ios.to_ascii_uppercase());
                } else if ios[8..16].eq("00000200") {
                    println!("  BC-NAND ({})", ios.to_ascii_uppercase());
                } else if ios[8..16].eq("00000201") {
                    println!("  BC-WFS ({})", ios.to_ascii_uppercase());
                }
                let tmd = emunand.get_title_tmd(hex::decode(ios)?.try_into().unwrap()).unwrap();
                println!("    Version: {}", tmd.title_version());
            }
            else {
                println!("  IOS{} ({})", u32::from_str_radix(&ios[8..16], 16)?, ios.to_ascii_uppercase());
                let tmd = emunand.get_title_tmd(hex::decode(ios)?.try_into().unwrap()).unwrap();
                println!("    Version: {} ({})", tmd.title_version(), title::versions::dec_to_standard(tmd.title_version(), ios, None).unwrap());
            }
        }
        println!();
    }
    let mut missing_ioses: Vec<String> = Vec::new();
    if !installed_titles.is_empty() {
        println!("Installed Titles:");
        for title in installed_titles {
            let ascii = String::from_utf8_lossy(&hex::decode(&title[8..16])?).to_string();
            let ascii_tid = if ascii.len() == 4 {
                Some(ascii)
            } else {
                None
            };
            if let Some(ascii_tid) = ascii_tid {
                println!("  {} ({})", title.to_uppercase(), ascii_tid);
            } else {
                println!("  {}", title.to_uppercase());
            }
            let tmd = emunand.get_title_tmd(hex::decode(&title)?.try_into().unwrap()).unwrap();
            println!("    Version: {}", tmd.title_version());
            let ios_tid = &hex::encode(tmd.ios_tid()).to_ascii_uppercase();
            print!("    Required IOS: IOS{} ({})", u32::from_str_radix(&hex::encode(&tmd.ios_tid()[4..8]), 16)?, ios_tid);
            if !installed_ioses.contains(ios_tid) {
                println!(" *");
                if !missing_ioses.contains(ios_tid) {
                    missing_ioses.push(String::from(ios_tid));
                }
            }
            else {
                println!();
            }
        }
        println!();
    }
    if !disc_titles.is_empty() {
        println!("Save data was found for the following disc titles:");
        for title in disc_titles {
            let ascii = String::from_utf8_lossy(&hex::decode(&title[8..16])?).to_string();
            let ascii_tid = if ascii.len() == 4 {
                Some(ascii)
            } else {
                None
            };
            if let Some(ascii_tid) = ascii_tid {
                println!("  {} ({})", title.to_uppercase(), ascii_tid);
            } else {
                println!("  {}", title.to_uppercase());
            }
        }
        println!();
    }
    // Finally, list IOSes that are required by an installed title but are not currently installed.
    // This message is sponsored by `rustii emunand install-missing`.
    if !missing_ioses.is_empty() {
        println!("Some titles installed are missing their required IOS. These missing IOSes are \
        marked with \"*\" in the title list above. If these IOSes are not installed, the titles \
        requiring them will not launch. The IOSes required but not installed are:");
        for missing in missing_ioses {
            println!("  IOS{} ({})",  u32::from_str_radix(&missing[8..16], 16)?, missing);
        }
        println!("Missing IOSes can be automatically installed using the install-missing command.");
    }
    Ok(())
}

pub fn install_missing(emunand: &str, vwii: &bool) -> Result<()> {
    let emunand_path = Path::new(emunand);
    if !emunand_path.exists() {
        bail!("Target EmuNAND directory \"{}\" could not be found.", emunand_path.display());
    }
    let emunand = emunand::EmuNAND::open(emunand_path.to_path_buf())?;
    // Determine Wii vs vWii EmuNAND.
    let vwii = if *vwii {
        true
    } else {
        match emunand.get_title_tmd([0, 0, 0, 1, 0, 0, 0, 2]) {
            Some(tmd) => {
                tmd.is_vwii()
            },
            None => {
                false
            }
        }
    };
    // Build a list of IOSes that are required by at least one installed title but are not
    // installed themselves. Then from there we can call the NUS download_title() function to
    // download and trigger an EmuNAND install for each of them.
    let categories = emunand.get_installed_titles();
    let mut installed_ioses: Vec<String> = Vec::new();
    let mut installed_titles: Vec<String> = Vec::new();
    for category in categories {
        if category.title_type == "00000001" {
            let mut ioses: Vec<u32> = Vec::new();
            for title in category.titles {
                if title == "00000002" {
                    installed_titles.push(format!("{}{}", category.title_type, title));
                } else if title != "00000001" {
                    ioses.push(u32::from_str_radix(&title, 16)?);
                }
            }
            ioses.sort();
            ioses.iter().for_each(|x| installed_ioses.push(format!("00000001{:08X}", x)));
        } else if category.title_type != "00010000" {
            category.titles.iter().for_each(|x| installed_titles.push(format!("{}{}", category.title_type, x)));
        }
    }
    let title_tmds: Vec<tmd::TMD> = installed_titles.iter().map(|x| emunand.get_title_tmd(hex::decode(x).unwrap().try_into().unwrap()).unwrap()).collect();
    let mut missing_ioses: Vec<u32> = title_tmds.iter()
        .filter(|x| !installed_ioses.contains(&hex::encode(x.ios_tid()).to_ascii_uppercase()))
        .map(|x| u32::from_str_radix(&hex::encode(&x.ios_tid()[4..8]), 16).unwrap()).collect();
    if missing_ioses.is_empty() {
        bail!("All required IOSes are already installed!");
    }
    missing_ioses.sort();
    // Because we don't need to install the same IOS for every single title that requires it.
    missing_ioses.dedup();
    let missing_tids: Vec<[u8; 8]> = {
        if vwii {
            missing_ioses.iter().map(|x| {
                let mut tid = [0u8; 8];
                tid[3] = 7;
                tid[4..8].copy_from_slice(&x.to_be_bytes());
                tid
            }).collect()
        } else {
            missing_ioses.iter().map(|x| {
                let mut tid = [0u8; 8];
                tid[3] = 1;
                tid[4..8].copy_from_slice(&x.to_be_bytes());
                tid
            }).collect()
        }
    };
    println!("Missing IOSes:");
    for ios in &missing_tids {
        println!("  IOS{} ({})", u32::from_str_radix(&hex::encode(&ios[4..8]), 16)?, hex::encode(ios).to_ascii_uppercase());
    }
    println!();
    for ios in missing_tids {
        println!("Downloading IOS{} ({})...", u32::from_str_radix(&hex::encode(&ios[4..8]), 16)?, hex::encode(ios).to_ascii_uppercase());
        let title = nus::download_title(ios, None, true)?;
        let version = title.tmd.title_version();
        println!("  Installing IOS{} ({}) v{}...", u32::from_str_radix(&hex::encode(&ios[4..8]), 16)?, hex::encode(ios).to_ascii_uppercase(), version);
        emunand.install_title(title, false)?;
        println!("  Installed IOS{} ({}) v{}!", u32::from_str_radix(&hex::encode(&ios[4..8]), 16)?, hex::encode(ios).to_ascii_uppercase(), version);
    }
    println!("\nAll missing IOSes have been installed!");
    Ok(())
}

pub fn install_title(wad: &str, emunand: &str, override_meta: &bool) -> Result<()> {
    let wad_path = Path::new(wad);
    if !wad_path.exists() {
        bail!("Source WAD \"{}\" could not be found.", wad_path.display());
    }
    let emunand_path = Path::new(emunand);
    if !emunand_path.exists() {
        bail!("Target EmuNAND directory \"{}\" could not be found.", emunand_path.display());
    }
    let wad_file = fs::read(wad_path).with_context(|| format!("Failed to open WAD file \"{}\" for reading.", wad_path.display()))?;
    let title = title::Title::from_bytes(&wad_file).with_context(|| format!("The provided WAD file \"{}\" appears to be invalid.", wad_path.display()))?;
    let emunand = emunand::EmuNAND::open(emunand_path.to_path_buf())?;
    emunand.install_title(title, *override_meta)?;
    println!("Successfully installed WAD \"{}\" to EmuNAND at \"{}\"!", wad_path.display(), emunand_path.display());
    Ok(())
}

pub fn uninstall_title(tid: &str, emunand: &str, remove_ticket: &bool) -> Result<()> {
    let emunand_path = Path::new(emunand);
    if !emunand_path.exists() {
        bail!("Target EmuNAND directory \"{}\" could not be found.", emunand_path.display());
    }
    let tid_as_path = Path::new(&tid);
    let tid_bin: [u8; 8] = if tid_as_path.exists() {
        let wad_file = fs::read(tid_as_path).with_context(|| format!("Failed to open WAD file \"{}\" for reading.", tid_as_path.display()))?;
        let title = title::Title::from_bytes(&wad_file).with_context(|| format!("The provided WAD file \"{}\" appears to be invalid.", tid_as_path.display()))?;
        title.tmd.title_id()
    } else {
        hex::decode(tid).with_context(|| "The specified Title ID is not valid! The Title ID must be in hex format.")?.try_into().unwrap()
    };
    let emunand = emunand::EmuNAND::open(emunand_path.to_path_buf())?;
    emunand.uninstall_title(tid_bin, *remove_ticket)?;
    println!("Successfully uninstalled title with Title ID \"{}\" from EmuNAND at \"{}\"!", hex::encode(tid_bin).to_ascii_uppercase(), emunand_path.display());
    Ok(())
}
