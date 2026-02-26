// archive/u8.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the U8 packing/unpacking commands in the rustii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use glob::glob;
use rustwii::archive::u8;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Pack a directory into a U8 archive
    Pack {
        /// The directory to pack into a U8 archive
        input: String,
        /// The name of the packed U8 archive
        output: String,
    },
    /// Unpack a U8 archive into a directory
    Unpack {
        /// The path to the U8 archive to unpack
        input: String,
        /// The directory to unpack the U8 archive to
        output: String,
    }
}

fn pack_dir_recursive(dir: &mut u8::U8Directory, in_path: PathBuf) -> Result<()> {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for entry in glob(&format!("{}/*", in_path.display()))?.flatten() {
        match fs::metadata(&entry) {
            Ok(meta) if meta.is_file() => files.push(entry),
            Ok(meta) if meta.is_dir() => dirs.push(entry),
            _ => {} // Anything that isn't a normal file/directory just gets ignored.
        }
    }
    for file in files {
        let node = u8::U8File::new(file.file_name().unwrap().to_str().unwrap().to_owned(), fs::read(file)?);
        dir.add_file(node);
    }
    for child_dir in dirs {
        let node = u8::U8Directory::new(child_dir.file_name().unwrap().to_str().unwrap().to_owned());
        let dir = dir.add_dir(node);
        pack_dir_recursive(dir, child_dir)?;
    }
    Ok(())
}

pub fn pack_u8_archive(input: &str, output: &str) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source directory \"{}\" could not be found.", in_path.display());
    }
    let out_path = PathBuf::from(output);
    let mut root_dir = u8::U8Directory::new(String::new());
    pack_dir_recursive(&mut root_dir, in_path.to_path_buf()).with_context(|| "A U8 archive could not be packed.")?;
    fs::write(&out_path, &root_dir.to_bytes()?).with_context(|| format!("Could not open output file \"{}\" for writing.", out_path.display()))?;
    println!("Successfully packed directory \"{}\" into U8 archive \"{}\"!", in_path.display(), out_path.display());
    Ok(())
}

fn unpack_dir_recursive(dir: &u8::U8Directory, out_path: PathBuf) -> Result<()> {
    let out_path = out_path.join(&dir.name);
    for file in &dir.files {
        fs::write(out_path.join(&file.name), &file.data).with_context(|| format!("Failed to write output file \"{}\".", &file.name))?;
    }
    for dir in &dir.dirs {
        if !out_path.join(&dir.name).exists() {
            fs::create_dir(out_path.join(&dir.name)).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
        }
        unpack_dir_recursive(dir, out_path.clone())?;
    }
    Ok(())
}

pub fn unpack_u8_archive(input: &str, output: &str) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source U8 archive \"{}\" could not be found.", in_path.display());
    }
    let out_path = PathBuf::from(output);
    if out_path.exists() {
        if !out_path.is_dir() {
            bail!("A file already exists with the specified directory name!");
        }
    } else {
        fs::create_dir(&out_path).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
    }
    // Extract the files and directories in the root, and then recurse over each directory to
    // extract the files and directories they contain.
    let root_dir = u8::U8Directory::from_bytes(fs::read(in_path).with_context(|| format!("Input file \"{}\" could not be read.", in_path.display()))?.into_boxed_slice())?;
    unpack_dir_recursive(&root_dir, out_path.clone())?;
    println!("Successfully unpacked U8 archive to directory \"{}\"!", out_path.display());
    Ok(())
}
