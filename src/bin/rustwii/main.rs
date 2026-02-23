// main.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Base for the rustii CLI that handles argument parsing and directs execution to the proper module.

mod archive;
mod title;
mod filetypes;
mod info;
mod nand;

use anyhow::Result;
use clap::{Subcommand, Parser};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
enum Commands {
    /// Decompress data using ASH compression
    Ash {
        #[command(subcommand)]
        command: archive::ash::Commands,
    },
    /// Manage Wii EmuNANDs
    Emunand {
        #[command(subcommand)]
        command: nand::emunand::Commands,
    },
    /// Fakesign a TMD, Ticket, or WAD (trucha bug)
    Fakesign {
        /// The path to a TMD, Ticket, or WAD
        input: String,
        /// An (optional) output name; defaults to overwriting input file if not provided
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Get information about a TMD, Ticket, or WAD
    Info {
        /// The path to a TMD, Ticket, or WAD
        input: String,
    },
    /// Compress/decompress data using LZ77 compression
    Lz77 {
        #[command(subcommand)]
        command: archive::lz77::Commands
    },
    /// Download data from the NUS
    Nus {
        #[command(subcommand)]
        command: title::nus::Commands
    },
    /// Manage setting.txt
    Setting {
        #[command(subcommand)]
        command: nand::setting::Commands
    },
    /// Edit a TMD file
    Tmd {
        #[command(subcommand)]
        command: title::tmd::Commands
    },
    /// Pack/unpack a U8 archive
    U8 {
        #[command(subcommand)]
        command: archive::u8::Commands
    },
    /// Pack/unpack/edit a WAD file
    Wad {
        #[command(subcommand)]
        command: title::wad::Commands,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Some(Commands::Ash { command }) => {
            match command {
                archive::ash::Commands::Compress { input, output } => {
                    archive::ash::compress_ash(input, output)?
                },
                archive::ash::Commands::Decompress { input, output } => {
                    archive::ash::decompress_ash(input, output)?
                }
            }
        },
        Some(Commands::Emunand { command }) => {
            match command {
                nand::emunand::Commands::Info { emunand } => {
                    nand::emunand::info(emunand)?
                },
                nand::emunand::Commands::InstallMissing { emunand, vwii } => {
                    nand::emunand::install_missing(emunand, vwii)?
                },
                nand::emunand::Commands::InstallTitle { wad, emunand, override_meta} => {
                    nand::emunand::install_title(wad, emunand, override_meta)?
                },
                nand::emunand::Commands::UninstallTitle { tid, emunand, remove_ticket } => {
                    nand::emunand::uninstall_title(tid, emunand, remove_ticket)?
                }
            }
        }
        Some(Commands::Fakesign { input, output }) => {
            title::fakesign::fakesign(input, output)?
        },
        Some(Commands::Info { input }) => {
            info::info(input)?
        },
        Some(Commands::Lz77 { command }) => {
            match command {
                archive::lz77::Commands::Compress { input, output } => {
                    archive::lz77::compress_lz77(input, output)?
                },
                archive::lz77::Commands::Decompress { input, output } => {
                    archive::lz77::decompress_lz77(input, output)?
                }
            }
        },
        Some(Commands::Nus { command }) => {
            match command {
                title::nus::Commands::Content { tid, cid, version, output, decrypt} => {
                    title::nus::download_content(tid, cid, version, output, decrypt)?  
                },
                title::nus::Commands::Ticket { tid, output } => {
                    title::nus::download_ticket(tid, output)?  
                },
                title::nus::Commands::Title { tid, version, output} => {
                    title::nus::download_title(tid, version, output)?
                }
                title::nus::Commands::Tmd { tid, version, output} => {
                    title::nus::download_tmd(tid, version, output)?
                }
            }
        },
        Some(Commands::Setting { command }) => {
            match command {
                nand::setting::Commands::Decrypt { input, output } => {
                    nand::setting::decrypt_setting(input, output)?;
                },
                nand::setting::Commands::Encrypt { input, output } => {
                    nand::setting::encrypt_setting(input, output)?;
                }
            }
        },
        Some(Commands::Tmd { command}) => {
            match command {
                title::tmd::Commands::Edit { input, output, edits} => {
                    title::tmd::tmd_edit(input, output, edits)?
                },
                title::tmd::Commands::Remove { input, output, identifier } => {
                    title::tmd::tmd_remove(input, output, identifier)?
                }
            }
        },
        Some(Commands::U8 { command }) => {
            match command {
                archive::u8::Commands::Pack { input, output } => {
                    archive::u8::pack_u8_archive(input, output)?
                },
                archive::u8::Commands::Unpack { input, output } => {
                    archive::u8::unpack_u8_archive(input, output)?
                }
            }
        },
        Some(Commands::Wad { command }) => {
            match command {
                title::wad::Commands::Add { input, content, output, cid, r#type } => {
                    title::wad::wad_add(input, content, output, cid, r#type)?
                },
                title::wad::Commands::Convert { input, target, output } => {
                    title::wad::wad_convert(input, target, output)?
                },
                title::wad::Commands::Edit { input, output, edits } => {
                    title::wad::wad_edit(input, output, edits)?
                },
                title::wad::Commands::Pack { input, output} => {
                    title::wad::wad_pack(input, output)?
                },
                title::wad::Commands::Remove { input, output, identifier } => {
                    title::wad::wad_remove(input, output, identifier)?
                },
                title::wad::Commands::Set { input, content, output, identifier, r#type} => {
                    title::wad::wad_set(input, content, output, identifier, r#type)?
                },
                title::wad::Commands::Unpack { input, output } => {
                    title::wad::wad_unpack(input, output)?
                },
            }
        },
        None => { /* Clap handles no passed command by itself */}
    }
    Ok(())
}
