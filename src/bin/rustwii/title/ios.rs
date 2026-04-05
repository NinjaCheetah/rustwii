// title/ios.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Code for the IOS patcher and cIOS build commands in the rustwii CLI.

use std::{env, fs};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use rustwii::title;
use rustwii::title::{crypto, iospatcher};
use rustwii::title::tmd::ContentType;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Build a cIOS from a provided base IOS and map
    Cios {
        /// The base IOS WAD
        base: String,
        /// The cIOS map file
        map: String,
        /// The cIOS version from the map to build
        cios_version: String,
        /// Path for the finished cIOS WAD
        output: String,
        /// Path to the directory containing the cIOS modules (optional, defaults to the current
        /// directory)
        #[arg(short, long)]
        modules: Option<String>,
        /// Slot that the cIOS will install to (optional, defaults to 249)
        #[arg(short, long)]
        slot: Option<u8>,
        /// IOS version the cIOS will have (optional, defaults to 65535)
        #[arg(short, long)]
        version: Option<u16>
    },
    /// Apply patches to an IOS
    Patch {
        /// The IOS WAD to apply patches to
        input: String,
        /// An optional output path; default to overwriting input file if not provided
        #[arg(short, long)]
        output: Option<String>,
        /// Set a new IOS version (0-65535)
        #[arg(short, long)]
        version: Option<u16>,
        /// Set the slot that this IOS will install into
        #[arg(short, long)]
        slot: Option<u8>,
        /// Set all patched content to be non-shared
        #[arg(short, long, action)]
        no_shared: bool,
        #[command(flatten)]
        enabled_patches: EnabledPatches,
    }
}

#[derive(Args)]
#[clap(next_help_heading = "Patches")]
#[group(multiple = true, required = false)]
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
    let tid = hex::encode(ios.tmd().title_id());

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

        // Set the type of the content containing ES to "Normal" to avoid it getting installed to
        // /shared1 on NAND.
        if *no_shared {
            set_type_normal(&mut ios, es_index)?;
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

        if *no_shared {
            set_type_normal(&mut ios, dip_index)?;
        }
    }

    println!("\nTotal patches applied: {patches_applied}");

    if patches_applied == 0 && version.is_none() && slot.is_none() {
        bail!("No patches were applied. Please make sure that any specified patches are compatible \
        with this IOS.")
    }

    ios.fakesign()?;
    fs::write(out_path, ios.to_wad()?.to_bytes()?)?;

    println!("IOS successfully patched!");
    Ok(())
}

fn set_type_normal(ios: &mut title::Title, index: usize) -> Result<()> {
    let mut content_records = ios.tmd().content_records().clone();
    content_records[index].content_type = ContentType::Normal;
    let mut tmd = ios.tmd().clone();
    tmd.set_content_records(content_records);
    ios.set_tmd(tmd);

    Ok(())
}

pub fn build_cios(
    base: &str,
    map: &str,
    cios_version: &str,
    output: &str,
    modules: &Option<String>,
    slot: &Option<u8>,
    version: &Option<u16>
) -> Result<()> {
    let base_path = Path::new(base);
    if !base_path.exists() {
        bail!("Source WAD \"{}\" does not exist.", base_path.display());
    }

    let map_path = Path::new(map);
    if !map_path.exists() {
        bail!("cIOS map file \"{}\" does not exist.", map_path.display());
    }

    let modules_path = if modules.is_some() {
        PathBuf::from(modules.clone().unwrap())
    } else {
        env::current_dir()?
    };
    if !modules_path.exists() {
        bail!("cIOS modules directory \"{}\" does not exist.", modules_path.display());
    }

    let out_path = Path::new(output);

    let mut ios = title::Title::from_bytes(&fs::read(base_path)?).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;

    let map_string = fs::read_to_string(map_path).with_context(|| "Failed to read cIOS map file! The file may be invalid.")?;
    let doc = roxmltree::Document::parse(&map_string).with_context(|| "Failed to parse cIOS map! The map may be invalid.")?;
    let root = doc.root_element();

    // Search the map for the specified cIOS version and bail if this map doesn't include it.
    let target_option = root.children().into_iter()
        .find(|x| x.attribute("name").unwrap_or("").eq(cios_version));
    let target_cios = if let Some(cios) = target_option {
        cios
    } else {
        bail!("The target cIOS \"{}\" could not be found in the provided map.", cios_version);
    };

    // Search the target cIOS for the base provided and return the node matching it, if found.
    let provided_base = format!("{}", ios.tmd().title_id().last().unwrap());
    let base_option = target_cios.children().into_iter()
        .find(|x| x.attribute("ios").unwrap_or("").eq(&provided_base));
    let target_base = if let Some(base) = base_option {
        base
    } else {
        bail!("The provided base (IOS{}) does not match any bases supported by the provided map.", provided_base);
    };

    // Check the IOS version required by the map against the version provided.
    let req_base_version = target_base.attribute("version")
        .unwrap_or("")
        .parse::<u16>().with_context(|| "Failed to parse required base version from map! The map may be invalid.")?;
    if ios.tmd().title_version() != req_base_version {
        bail!("The provided base (IOS{} v{}) doesn't match the required version, v{}",
            provided_base,
            ios.tmd().title_version(),
            req_base_version
        );
    }

    println!("Building cIOS \"{cios_version}\" from base IOS{provided_base} v{req_base_version}...");

    println!(" - Patching existing modules...");
    let content_with_patches: Vec<roxmltree::Node> = target_base.children()
        .filter(|x| x.has_attribute("patchscount")) // yes, this typo is really in the maps
        .collect();
    for content in content_with_patches {
        let cid = u32::from_str_radix(
            content.attribute("id").unwrap().trim_start_matches("0x"),
            16
        )?;
        let target_content = ios.get_content_by_cid(cid)?;
        let mut buf = Cursor::new(target_content);

        // Iterate over the patches. Another filter happens here just to be sure that this node's
        // children are all actually patches.
        for patch in content.children().filter(|x| x.tag_name().name().eq("patch")) {
            // Now we need to do some "fun" parsing stuff to get the find and replace bytes from the map.

            // This block currently omitted because I don't really think it's necessary? The map
            // contains the replacement bytes and the offset to write them at, so using the find
            // bytes seems unnecessary.
            // let find_strs: Vec<&str> = patch.attribute("originalbytes").unwrap().split(",").collect();
            // let find_seq: Vec<u8> = find_strs.iter()
            //     .map(|x| x.trim_start_matches("0x"))
            //     .map(|x| u8::from_str_radix(x, 16).unwrap())
            //     .collect();

            let replace_strs: Vec<&str> = patch.attribute("newbytes").unwrap().split(",").collect();
            let replace_seq: Vec<u8> = replace_strs.iter()
                .map(|x| x.trim_start_matches("0x"))
                .map(|x| u8::from_str_radix(x, 16).unwrap())
                .collect();

            let offset = u64::from_str_radix(
                patch.attribute("offset").unwrap().trim_start_matches("0x"),
                16
            )?;
            buf.seek(SeekFrom::Start(offset))?;
            buf.write_all(&replace_seq)?;
        }

        // Done with patches for this content, so put it back into the title.
        let idx = ios.tmd().get_index_from_cid(cid)?;
        ios.set_content(buf.get_ref(), idx, None, Some(ContentType::Normal))?;
    }
    println!("   - Done.");

    println!(" - Adding required additional modules...");
    let content_new_modules: Vec<roxmltree::Node> = target_base.children()
        .filter(|x| x.has_attribute("module"))
        .collect();
    for content in content_new_modules {
        let target_index = content.attribute("tmdmoduleid").unwrap().parse::<i32>()?;
        let cid = u32::from_str_radix(
            content.attribute("id").unwrap().trim_start_matches("0x"),
            16
        )?;

        let module_path = modules_path.join(content.attribute("module").unwrap_or(""))
            .with_extension("app");
        if !module_path.exists() {
            bail!("The required cIOS module \"{}\" could not be found.", module_path.file_name().unwrap().display());
        }

        let module = fs::read(module_path)?;
        if target_index == -1 {
            ios.add_content(&module, cid, ContentType::Normal)?;
        } else {
            let existing_module = ios.get_content_by_index(target_index as usize)?;
            let existing_cid = ios.tmd().content_records()[target_index as usize].content_id;
            let existing_type = ios.tmd().content_records()[target_index as usize].content_type;
            ios.set_content(&module, target_index as usize, Some(cid), Some(ContentType::Normal))?;
            ios.add_content(&existing_module, existing_cid, existing_type)?;
        }
    }
    println!("   - Done.");

    println!(" - Setting cIOS' properties...");
    // Set the cIOS' slot and version to the specified values.
    let slot = if let Some(slot) = slot && *slot >= 3 {
        if *slot >= 3 {
            *slot
        } else {
            println!("Warning: Ignoring invalid slot \"{slot}\", using default slot 249 instead.");
            249
        }
    } else {
        249
    };

    let version = if let Some(version) = version {
        *version
    } else {
        65535
    };

    let tid = hex::decode(format!("00000001{slot:08X}"))?;
    ios.set_title_id(tid.try_into().unwrap()).expect("Failed to set IOS slot!");
    println!("   - Set cIOS slot: {slot}");

    ios.set_title_version(version);
    println!("   - Set cIOS version: {version}");

    println!("   - Done.");

    // If this is a vWii cIOS, then we need to re-encrypt it with the regular Wii common key so that
    // it could be installed from within Wii mode with a normal WAD installer.
    if ios.ticket().common_key_index() == 2 {
        let title_key_dec = ios.ticket().title_key_dec();
        let title_key_common = crypto::encrypt_title_key(title_key_dec, 0, ios.tmd().title_id(), false);
        let mut ticket = ios.ticket().clone();
        ticket.set_title_key(title_key_common);
        ticket.set_common_key_index(0);
        ios.set_ticket(ticket);
    }

    ios.fakesign()?;
    fs::write(out_path, ios.to_wad()?.to_bytes()?)?;

    println!("Successfully built cIOS \"{cios_version}\"!");

    Ok(())
}
