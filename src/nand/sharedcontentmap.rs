// nand/sharedcontentmap.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements shared content map parsing and editing to update the records of what content is
// installed at /shared1/ on NAND.

use std::io::{Cursor, Read, Write};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedContentError {
    #[error("content.map is an invalid length and cannot be parsed")]
    InvalidSharedContentMapLength,
    #[error("found invalid shared content name `{0}`")]
    InvalidSharedContentName(String),
    #[error("shared content map is not in a valid format")]
    IO(#[from] std::io::Error),
}

#[derive(Debug)]
/// A structure that represents a shared Content ID/content hash pairing in a content.map file.
pub struct ContentMapEntry {
    pub shared_id: u32,
    pub hash: [u8; 20],
}

/// A structure that allows for parsing and editing a /shared1/content.map file.
pub struct SharedContentMap {
    pub records: Vec<ContentMapEntry>,
}

impl Default for SharedContentMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedContentMap {
    /// Creates a new SharedContentMap instance from the binary data of a content.map file.
    pub fn from_bytes(data: &[u8]) -> Result<SharedContentMap, SharedContentError> {
        // The uid.sys file must be divisible by a multiple of 28, or something is wrong, since each
        // entry is 28 bytes long.
        if !data.len().is_multiple_of(28) {
            return Err(SharedContentError::InvalidSharedContentMapLength);
        }
        let record_count = data.len() / 28;
        let mut buf = Cursor::new(data);
        let mut records: Vec<ContentMapEntry> = Vec::new();
        for _ in 0..record_count {
            // This requires some convoluted parsing, because Nintendo represents the file names as
            // actual chars and not numbers, despite the fact that the names are always numbers and
            // using numbers would make incrementing easier. Read the names in as a string, and then
            // parse that hex string into a u32.
            let mut shared_id_bytes = [0u8; 8];
            buf.read_exact(&mut shared_id_bytes)?;
            let shared_id_str = String::from_utf8_lossy(&shared_id_bytes);
            let shared_id = match u32::from_str_radix(&shared_id_str, 16) {
                Ok(id) => id,
                Err(_) => return Err(SharedContentError::InvalidSharedContentName(shared_id_str.to_string())),
            };
            let mut hash = [0u8; 20];
            buf.read_exact(&mut hash)?;
            records.push(ContentMapEntry { shared_id, hash });
        }
        Ok(SharedContentMap { records })
    }

    /// Creates a new, empty SharedContentMap instance that can then be populated.
    pub fn new() -> Self {
        SharedContentMap { records: Vec::new() }
    }

    /// Dumps the data in a SharedContentMap back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        for record in self.records.iter() {
            let shared_id = format!("{:08X}", record.shared_id).to_ascii_lowercase();
            buf.write_all(shared_id.as_bytes())?;
            buf.write_all(&record.hash)?;
        }
        Ok(buf)
    }

    /// Adds new shared content to content.map, and assigns it a new file name. The new content
    /// will only be added if its hash is not already present in the file. Returns None if the
    /// content hash was already present, or the assigned file name if the hash was just added.
    pub fn add(&mut self, hash: &[u8; 20]) -> Result<Option<String>, SharedContentError> {
        // Return None if the hash is already accounted for.
        if self.records.iter().any(|entry| entry.hash == *hash) {
            return Ok(None);
        }
        // Find the highest index (represented by the file name) and increment it to choose the
        // name for the new shared content.
        let max_index = self.records.iter()
            .max_by_key(|record| record.shared_id)
            .map(|record| record.shared_id + 1)
            .unwrap_or(0);
        self.records.push(ContentMapEntry {
            shared_id: max_index,
            hash: *hash,
        });
        Ok(Some(format!("{:08X}", max_index)))
    }
}
