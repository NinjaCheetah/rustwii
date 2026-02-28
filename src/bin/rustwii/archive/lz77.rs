// archive/lz77.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the LZ77 compression/decompression commands in the rustwii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use rustwii::archive::lz77;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Compress a file with LZ77 compression
    Compress {
        /// The path to the file to compress
        input: String,
        /// An optional output name; defaults to <input name>.lz77
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Decompress an LZ77-compressed file
    Decompress {
        /// The path to the file to decompress
        input: String,
        /// An optional output name; defaults to <input name>.out
        #[arg(short, long)]
        output: Option<String>,
    }
}

pub fn compress_lz77(input: &str, output: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Input file \"{}\" could not be found.", in_path.display());
    }
    let decompressed = fs::read(in_path)?;
    let compressed = lz77::compress_lz77(&decompressed).with_context(|| "An unknown error occurred while compressing the data.")?;
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap())
    } else {
        PathBuf::from(in_path).with_extension(format!("{}.lz77", in_path.extension().unwrap_or("".as_ref()).to_str().unwrap()))
    };
    fs::write(out_path.clone(), compressed)?;
    println!("Successfully compressed file to \"{}\"!", out_path.display());
    Ok(())
}

pub fn decompress_lz77(input: &str, output: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Compressed file \"{}\" could not be found.", in_path.display());
    }
    let compressed = fs::read(in_path)?;
    let decompressed = lz77::decompress_lz77(&compressed).with_context(|| "An unknown error occurred while decompressing the data.")?;
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap())
    } else {
        PathBuf::from(in_path.file_name().unwrap()).with_extension(format!("{}.out", in_path.extension().unwrap_or("".as_ref()).to_str().unwrap()))
    };
    fs::write(out_path.clone(), decompressed)?;
    println!("Successfully decompressed LZ77 file to \"{}\"!", out_path.display());
    Ok(())
}
