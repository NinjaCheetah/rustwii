// title/iospatcher.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Module for applying patches to IOSes using a Title.

use std::io::{Cursor, Seek, SeekFrom, Write};
use thiserror::Error;
use crate::title;
use crate::title::content;

#[derive(Debug, Error)]
pub enum IOSPatcherError {
    #[error("this title is not an IOS")]
    NotIOS,
    #[error("the required module \"{0}\" could not be found, this may not be a valid IOS")]
    ModuleNotFound(String),
    #[error("failed to get IOS content")]
    Content(#[from] content::ContentError),
    #[error("failed to set content in Title")]
    Title(#[from] title::TitleError),
    #[error("IOS content is invalid")]
    IO(#[from] std::io::Error),
}

pub fn ios_find_module(module_keyword: String, ios: &title::Title) -> Result<usize, IOSPatcherError> {
    let content_records = ios.tmd.content_records();
    let tid = hex::encode(ios.tmd.title_id());

    // If the TID is not a valid IOS TID, then return NotIOS. It's possible that this could catch
    // some modified IOSes that currently have a non-IOS TID but that's weird and if you're doing
    // that please stop.
    if !tid[..8].eq("00000001") || tid[8..].eq("00000001") || tid[8..].eq("00000002") {
        return Err(IOSPatcherError::NotIOS);
    }

    // Find the module's keyword in the content, and return the (true) index of the content that
    // it was found in.
    let keyword = module_keyword.as_bytes();
    for record in content_records {
        let content_decrypted = ios.get_content_by_index(record.index as usize)?;
        let offset = content_decrypted
            .windows(keyword.len())
            .position(|window| window == keyword);
        if offset.is_some() {
            return Ok(record.index as usize);
        }
    }

    // If we didn't return early by finding the offset, then return a ModuleNotFound error.
    Err(IOSPatcherError::ModuleNotFound(module_keyword))
}

fn ios_apply_patches(
    target_content: &mut Cursor<Vec<u8>>,
    find_seq: Vec<Vec<u8>>,
    replace_seq: Vec<Vec<u8>>
) -> Result<i32, IOSPatcherError> {
    let mut patch_count = 0;
    for idx in 0..find_seq.len() {
        let offset = target_content.get_ref()
            .windows(find_seq[idx].len())
            .position(|window| window == find_seq[idx]);
        if let Some(offset) = offset {
            target_content.seek(SeekFrom::Start(offset as u64))?;
            target_content.write_all(&replace_seq[idx])?;
            patch_count += 1;
        }
    }

    Ok(patch_count)
}

pub fn ios_patch_sigchecks(ios: &mut title::Title, es_index: usize) -> Result<i32, IOSPatcherError> {
    let target_content = ios.get_content_by_index(es_index)?;
    let mut buf = Cursor::new(target_content);

    let find_seq = vec![vec![0x20, 0x07, 0x23, 0xa2], vec![0x20, 0x07, 0x4b, 0x0b]];
    let replace_seq: Vec<Vec<u8>> = vec![vec![0x20, 0x00, 0x23, 0xa2], vec![0x20, 0x00, 0x4b, 0x0b]];
    let patch_count = ios_apply_patches(&mut buf, find_seq, replace_seq)?;

    ios.set_content(buf.get_ref(), es_index, None, None)?;

    Ok(patch_count)
}

pub fn ios_patch_es_identify(ios: &mut title::Title, es_index: usize) -> Result<i32, IOSPatcherError> {
    let target_content = ios.get_content_by_index(es_index)?;
    let mut buf = Cursor::new(target_content);

    let find_seq = vec![vec![0x28, 0x03, 0xd1, 0x23]];
    let replace_seq = vec![vec![0x28, 0x03, 0x00, 0x00]];
    let patch_count = ios_apply_patches(&mut buf, find_seq, replace_seq)?;

    ios.set_content(buf.get_ref(), es_index, None, None)?;

    Ok(patch_count)
}

pub fn ios_patch_dev_flash(ios: &mut title::Title, es_index: usize) -> Result<i32, IOSPatcherError> {
    let target_content = ios.get_content_by_index(es_index)?;
    let mut buf = Cursor::new(target_content);

    let find_seq = vec![vec![0x42, 0x8b, 0xd0, 0x01, 0x25, 0x66]];
    let replace_seq = vec![vec![0x42, 0x8b, 0xe0, 0x01, 0x25, 0x66]];
    let patch_count = ios_apply_patches(&mut buf, find_seq, replace_seq)?;

    ios.set_content(buf.get_ref(), es_index, None, None)?;

    Ok(patch_count)
}

pub fn ios_patch_allow_downgrade(ios: &mut title::Title, es_index: usize) -> Result<i32, IOSPatcherError> {
    let target_content = ios.get_content_by_index(es_index)?;
    let mut buf = Cursor::new(target_content);

    let find_seq = vec![vec![0xd2, 0x01, 0x4e, 0x56]];
    let replace_seq = vec![vec![0xe0, 0x01, 0x4e, 0x56]];
    let patch_count = ios_apply_patches(&mut buf, find_seq, replace_seq)?;

    ios.set_content(buf.get_ref(), es_index, None, None)?;

    Ok(patch_count)
}

pub fn ios_patch_drive_inquiry(ios: &mut title::Title, dip_index: usize) -> Result<i32, IOSPatcherError> {
    let target_content = ios.get_content_by_index(dip_index)?;
    let mut buf = Cursor::new(target_content);

    let find_seq = vec![vec![0x49, 0x4c, 0x23, 0x90, 0x68, 0x0a]];
    let replace_seq = vec![vec![0x20, 0x00, 0xe5, 0x38, 0x68, 0x0a]];
    let patch_count = ios_apply_patches(&mut buf, find_seq, replace_seq)?;

    ios.set_content(buf.get_ref(), dip_index, None, None)?;

    Ok(patch_count)
}
