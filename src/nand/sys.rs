// nand/sys.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for parsing and editing files in /sys/ on the
// Wii's NAND.

use std::io::{Cursor, Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UidSysError {
    #[error("uid.sys is an invalid length and cannot be parsed")]
    InvalidUidSysLength,
    #[error("uid.sys data is not in a valid format")]
    IO(#[from] std::io::Error),
}

/// A structure that represents a Title ID/UID pairing in a uid.sys file.
pub struct UidSysEntry {
    pub title_id: [u8; 8],
    pub uid: u32,
}

/// A structure that allows for creating, parsing, and editing a /sys/uid.sys file.
pub struct UidSys {
    entries: Vec<UidSysEntry>,
}

impl Default for UidSys {
    fn default() -> Self {
        Self::new()
    }
}

impl UidSys {
    /// Creates a new UidSys instance from the binary data of a uid.sys file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, UidSysError> {
        // The uid.sys file must be divisible by a multiple of 12, or something is wrong, since each
        // entry is 12 bytes long.
        if !data.len().is_multiple_of(12) {
            return Err(UidSysError::InvalidUidSysLength);
        }
        let entry_count = data.len() / 12;
        let mut buf = Cursor::new(data);
        let mut entries: Vec<UidSysEntry> = Vec::new();
        for _ in 0..entry_count {
            let mut title_id = [0u8; 8];
            buf.read_exact(&mut title_id)?;
            let uid = buf.read_u32::<BigEndian>()?;
            entries.push(UidSysEntry { title_id, uid });
        }
        Ok(UidSys { entries })
    }
    
    /// Creates a new UidSys instance and initializes it with the default entry of the Wii Menu
    /// (0000000100000002) with UID 0x1000.
    pub fn new() -> Self {
        let mut uid_sys = UidSys { entries: Vec::new() };
        uid_sys.add(&[0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2]).unwrap();
        uid_sys
    }
    
    /// Dumps the data in a UidSys back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UidSysError> {
        let mut buf: Vec<u8> = Vec::new();
        for entry in self.entries.iter() {
            buf.write_all(&entry.title_id)?;
            buf.write_u32::<BigEndian>(entry.uid)?;
        }
        Ok(buf)
    }
    
    /// Adds a new Title ID to uid.sys, and assigns it a new UID. The new Title ID will only be 
    /// added if it is not already present in the file. Returns None if the Title ID was already
    /// present, or the newly assigned UID if the Title ID was just added.
    pub fn add(&mut self, title_id: &[u8; 8]) -> Result<Option<u32>, UidSysError> {
        // Return None if the Title ID is already accounted for.
        if self.entries.iter().any(|entry| entry.title_id == *title_id) {
            return Ok(None);
        }
        // Find the highest UID and increment it to choose the UID for the new Title ID.
        let max_uid = self.entries.iter()
            .max_by_key(|entry| entry.uid)
            .map(|entry| entry.uid)
            .unwrap_or(4095);
        self.entries.push(UidSysEntry {
            title_id: *title_id,
            uid: max_uid + 1,
        });
        Ok(Some(max_uid + 1))
    }
}
