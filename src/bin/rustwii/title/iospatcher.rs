// title/iospatcher.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the iospatcher command in the rustwii CLI.

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Args;
use rustwii::title;
use rustwii::title::iospatcher;

#[derive(Args)]
#[clap(next_help_heading = "Patches")]
#[group(multiple = true, required = true)]
/// Modifications that can be made to a title, shared between the WAD and TMD commands.
pub struct EnabledPatches {
    /// Patch out signature checks
    #[arg(long, action)]
    sig_checks: bool,
    /// Patch in access to ES_Identify
    #[arg(long, action)]
    es_identify: bool,
    /// Patch in access to /dev/flash
    #[arg(long, action)]
    dev_flash: bool,
    /// Patch out anti-downgrade checks
    #[arg(long, action)]
    allow_downgrade: bool,
    /// Patch out drive inquiries (EXPERIMENTAL)
    #[arg(long, action)]
    drive_inquiry: bool,
}

pub fn patch_ios(
    input: &str,
    output: &Option<String>,
    version: &Option<u16>,
    slot: &Option<u8>,
    no_shared: &bool,
    enabled_patches: &EnabledPatches,
) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source WAD \"{}\" does not exist.", in_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap()).with_extension("wad")
    } else {
        in_path.to_path_buf()
    };

    let mut ios = title::Title::from_bytes(&fs::read(in_path)?).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
    let tid = hex::encode(ios.tmd.title_id());

    // If the TID is not a valid IOS TID, then bail.
    if !tid[..8].eq("00000001") || tid[8..].eq("00000001") || tid[8..].eq("00000002") {
        bail!("The provided WAD does not appear to contain an IOS! No patches can be applied.")
    }

    let mut patches_applied = 0;

    if let Some(version) = version {
        ios.set_title_version(*version);
        println!("Set new IOS version: {version}")
    }

    if let Some(slot) = slot && *slot >= 3 {
        let tid = hex::decode(format!("00000001{slot:08X}"))?;
        ios.set_title_id(tid.try_into().unwrap()).expect("Failed to set IOS slot!");
        println!("Set new IOS slot: {slot}");
    }

    if enabled_patches.sig_checks ||
        enabled_patches.es_identify ||
        enabled_patches.dev_flash ||
        enabled_patches.allow_downgrade
    {
        let es_index = iospatcher::ios_find_module(String::from("ES:"), &ios)
            .with_context(|| "The ES module could not be found. This WAD is not a valid IOS.")?;
        if enabled_patches.sig_checks {
            print!("Applying signature check patch... ");
            let count = iospatcher::ios_patch_sigchecks(&mut ios, es_index)?;
            println!("{} patch(es) applied", count);
            patches_applied += count;
        }
        if enabled_patches.es_identify {
            print!("Applying ES_Identify access patch... ");
            let count = iospatcher::ios_patch_es_identify(&mut ios, es_index)?;
            println!("{} patch(es) applied", count);
            patches_applied += count;
        }
        if enabled_patches.dev_flash {
            print!("Applying /dev/flash access patch... ");
            let count = iospatcher::ios_patch_dev_flash(&mut ios, es_index)?;
            println!("{} patch(es) applied", count);
            patches_applied += count;
        }
        if enabled_patches.allow_downgrade {
            print!("Applying allow downgrading patch... ");
            let count = iospatcher::ios_patch_allow_downgrade(&mut ios, es_index)?;
            println!("{} patch(es) applied", count);
            patches_applied += count;
        }
    }

    if enabled_patches.drive_inquiry {
        let dip_index = iospatcher::ios_find_module(String::from("DIP:"), &ios)
            .with_context(|| "The DIP module could not be found. This WAD is not a valid IOS, \
             or this IOS version does not use the DIP module.")?;
        print!("Applying (EXPERIMENTAL) drive inquiry patch... ");
        let count = iospatcher::ios_patch_drive_inquiry(&mut ios, dip_index)?;
        println!("{} patch(es) applied", count);
        patches_applied += count;
    }

    println!("\nTotal patches applied: {patches_applied}");

    if patches_applied == 0 && version.is_none() && slot.is_none() {
        bail!("No patchers were applied. Please make sure the specified patches are compatible \
        with this IOS.")
    }

    ios.fakesign()?;
    fs::write(out_path, ios.to_wad()?.to_bytes()?)?;

    println!("IOS successfully patched!");
    Ok(())
}
