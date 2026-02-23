// archive/ash.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the ASH decompression command in the rustii CLI.
// Might even have the compression command someday if I ever write the compression code!

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use rustwii::archive::ash;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Compress a file with ASH compression (NOT IMPLEMENTED)
    Compress {
        /// The path to the file to compress
        input: String,
        /// An optional output name; defaults to <input name>.ash
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Decompress an ASH-compressed file
    Decompress {
        /// The path to the file to decompress
        input: String,
        /// An optional output name; defaults to <input name>.out
        #[arg(short, long)]
        output: Option<String>,
    }
}

pub fn compress_ash(_input: &str, _output: &Option<String>) -> Result<()> {
    todo!();
}

pub fn decompress_ash(input: &str, output: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Compressed file \"{}\" could not be found.", in_path.display());
    }
    let compressed = fs::read(in_path)?;
    let decompressed = ash::decompress_ash(&compressed, None, None).with_context(|| "An unknown error occurred while decompressing the data.")?;
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap())
    } else {
        PathBuf::from(in_path.file_name().unwrap()).with_extension(format!("{}.out", in_path.extension().unwrap_or("".as_ref()).to_str().unwrap()))
    };
    fs::write(out_path.clone(), decompressed)?;
    println!("Successfully decompressed ASH file to \"{}\"!", out_path.display());
    Ok(())
}
