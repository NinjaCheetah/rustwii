// archive/theme.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the theme building commands in the rustwii CLI.

use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use ini::{Ini, ParseOption};
use tempfile::Builder;
use zip::ZipArchive;
use rustwii::archive::{ash, lz77, u8};
use crate::archive::u8::{pack_dir_recursive, unpack_dir_recursive};

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Apply an MYM theme to the Wii Menu
    ApplyMym {
        /// The path to the source MYM file to apply
        mym: String,
        /// The path to the base Wii Menu asset archive (000000xx.app)
        base: String,
        /// The file to output the finished theme to (<filename>.csm)
        output: String,
    }
}

pub fn theme_apply_mym(mym: &str, base: &str, output: &str) -> Result<()> {
    let mym_path = Path::new(mym);
    if !mym_path.exists() {
        bail!("Theme file \"{}\" could not be found.", mym);
    }

    let base_path = Path::new(base);
    if !base_path.exists() {
        bail!("Base asset file \"{}\" could not be found.", base);
    }

    let out_path = PathBuf::from(output);

    // Create the temporary work directory and extract the mym file to it.
    let work_dir = Builder::new().prefix("mym_apply_").tempdir()?;
    let mym_dir = work_dir.path().join("mym_work");
    let mym_buf = fs::read(mym_path).with_context(|| format!("Failed to open theme file \"{}\" for reading.", mym_path.display()))?;
    ZipArchive::extract(&mut ZipArchive::new(Cursor::new(mym_buf))?, &mym_dir)?;

    // Load the mym ini file. Escapes have to be disabled so that Windows-formatted paths are
    // loaded correct.
    let mym_ini = Ini::load_from_file_opt(
        mym_dir.join("mym.ini"),
        ParseOption { enabled_escape: false, ..Default::default() }
    ).with_context(|| "Failed to load theme config file. This theme may be invalid!")?;

    // Extract the base asset archive to the temporary dir.
    let base_dir = work_dir.path().join("base_work");
    fs::create_dir(&base_dir)?;
    let assets_u8 = u8::U8Directory::from_bytes(fs::read(base_path).with_context(|| format!("Base asset file \"{}\" could not be read.", base_path.display()))?.into_boxed_slice())?;
    unpack_dir_recursive(&assets_u8, base_dir.clone()).expect("Failed to extract base assets, they may be invalid!");

    // Store any nested containers that we extract so that they can be re-packed later.
    let mut extracted_containers: HashMap<String, PathBuf> = HashMap::new();

    // Iterate through the ini file and apply modifications as necessary.
    for (sec, prop) in mym_ini.iter() {
        if let Some(sec) = sec {
            if sec.contains("sdta") {
                // Validate that the file and source keys exist, and then build a path to the
                // source file.
                if !prop.contains_key("file") || !prop.contains_key("source") {
                    bail!("Theme config entry \"{}\" is invalid and cannot be applied.", sec)
                }
                let source_parts: Vec<&str> = prop.get("source").unwrap().split("\\").collect();
                let mut source_path = mym_dir.clone();
                source_path.extend(source_parts);

                if !source_path.exists() {
                    bail!("Required source file \"{}\" could not be found! This theme may be invalid.", prop.get("source").unwrap())
                }

                println!("Applying static data file \"{}\" from theme...", source_path.file_name().unwrap().to_str().unwrap());
                let target_parts: Vec<&str> = prop.get("file").unwrap().split("\\").collect();
                let mut target_path = base_dir.clone();
                target_path.extend(target_parts);
                fs::copy(source_path, target_path).expect("Failed to copy asset from theme.");
            } else if sec.contains("cont") {
                // Validate that the file key exists and that container specified exists.
                if !prop.contains_key("file") {
                    bail!("Theme config entry \"{}\" is invalid and cannot be applied.", sec)
                }
                let container_parts: Vec<&str> = prop.get("file").unwrap().split("\\").collect();
                let mut container_path = base_dir.clone();
                container_path.extend(container_parts);

                if !container_path.exists() {
                    bail!("Required base container \"{}\" could not be found! The base assets or theme may be invalid.", prop.get("file").unwrap())
                }

                // Buffer in the container file, check its magic number, and decompress it if
                // necessary.
                println!("Unpacking base container \"{}\" for modification...", container_path.file_name().unwrap().to_str().unwrap());
                let container_data = fs::read(&container_path)?;
                let decompressed_container = if &container_data[0..4] == b"LZ77" {
                    println!(" - Decompressing LZ77 data...");
                    lz77::decompress_lz77(&container_data)?
                } else if &container_data[0..4] == b"ASH0" {
                    println!(" - Decompressing ASH data...");
                    ash::decompress_ash(&container_data, None, None)?
                } else {
                    container_data
                };

                // Load the unpacked archive, bailing if it still isn't a U8 archive.
                if &decompressed_container[0..4] != b"\x55\xAA\x38\x2D" {
                    bail!("Required base container \"{}\" is not a U8 archive. The base assets may be invalid.", container_path.file_name().unwrap().display())
                }

                // Extracted container name should follow the format:
                //      <file_name>_<extension>_out
                let extracted_container_name = container_path
                    .file_name().unwrap()
                    .to_str().unwrap().replace(".", "_")
                    + "_out";
                let extracted_container_path = container_path.parent().unwrap().join(extracted_container_name);
                fs::create_dir(&extracted_container_path)?;
                let u8_root = u8::U8Directory::from_bytes(decompressed_container.into_boxed_slice()).with_context(|| "Failed to extract base container! The base assets may be invalid.")?;

                // Finally, unpack the specified container to the created path and register it as
                // an extracted container so that we can repack it later.
                unpack_dir_recursive(&u8_root, extracted_container_path.clone())?;
                extracted_containers.insert(
                    container_path.file_name().unwrap().to_str().unwrap().to_owned(),
                    extracted_container_path
                );
                println!(" - Done.");
            } else {
                bail!("Theme config file contains unknown or unsupported key \"{}\"!", sec)
            }
        }
    }

    // Iterate over any containers we unpacked so we can repack them and clean up the unpacked
    // folder.
    println!("Repacking extracted containers...");
    for container in extracted_containers {
        // Add the original file name to the parent of the extracted dir, and that's where the
        // repacked container should go.
        println!(" - Repacking container \"{}\"...", container.0);
        let repacked_container_path = container.1.parent().unwrap().join(container.0.clone());
        let mut u8_root = u8::U8Directory::new(String::new());
        pack_dir_recursive(&mut u8_root, container.1.clone()).with_context(|| format!("Failed to repack extracted base container \"{}\". An unknown error occurred.", container.0))?;

        // Always compress the repacked archive with LZ77 compression.
        let compressed_container = lz77::compress_lz77(&u8_root.to_bytes()?)?;
        fs::write(repacked_container_path, compressed_container)?;

        // Erase the extracted container directory so it doesn't get packed into the final themed
        // archive.
        fs::remove_dir_all(container.1)?;
        println!(" - Done.");
    }

    // Theme applied, re-pack the base dir and write it out to the specified path.
    let mut finished_u8 = u8::U8Directory::new(String::new());
    pack_dir_recursive(&mut finished_u8, base_dir).expect("Failed to pack finalized theme!");
    fs::write(&out_path, &finished_u8.to_bytes()?).with_context(|| format!("Could not open output file \"{}\" for writing.", out_path.display()))?;
    println!("\nSuccessfully applied theme \"{}\" to output file \"{}\"!", mym, output);

    Ok(())
}
