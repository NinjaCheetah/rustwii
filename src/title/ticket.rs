// title/tik.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for Ticket parsing and editing.

use std::io::{Cursor, Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha1::{Sha1, Digest};
use thiserror::Error;
use crate::title::crypto;
use crate::title::crypto::decrypt_title_key;

#[derive(Debug, Error)]
pub enum TicketError {
    #[error("Ticket is version `{0}` but only v0 is supported")]
    UnsupportedVersion(u8),
    #[error("Ticket data could not be fakesigned")]
    CannotFakesign,
    #[error("signature issuer string must not exceed 64 characters (was {0})")]
    IssuerTooLong(usize),
    #[error("Ticket data is not in a valid format")]
    IO(#[from] std::io::Error),
}

#[derive(Debug, Copy, Clone)]
pub struct TitleLimit {
    // The type of limit being applied (time, launch count, etc.)
    pub limit_type: u32,
    // The maximum value for that limit (seconds, max launches, etc.)
    pub limit_max: u32,
}

#[derive(Debug)]
/// A structure that represents a Wii Ticket file.
pub struct Ticket {
    signature_type: u32,
    signature: [u8; 256],
    padding1: [u8; 60],
    signature_issuer: [u8; 64],
    ecdh_data: [u8; 60],
    ticket_version: u8,
    reserved1: [u8; 2],
    title_key: [u8; 16],
    unknown1: [u8; 1],
    ticket_id: [u8; 8],
    console_id: [u8; 4],
    title_id: [u8; 8],
    unknown2: [u8; 2],
    title_version: u16,
    permitted_titles_mask: [u8; 4],
    permit_mask: [u8; 4],
    title_export_allowed: u8,
    common_key_index: u8,
    unknown3: [u8; 48],
    content_access_permission: [u8; 64],
    padding2: [u8; 2],
    title_limits: [TitleLimit; 8],
}

impl Ticket {
    /// Creates a new Ticket instance from the binary data of a Ticket file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TicketError> {
        let mut buf = Cursor::new(data);
        let signature_type = buf.read_u32::<BigEndian>().map_err(TicketError::IO)?;
        let mut signature = [0u8; 256];
        buf.read_exact(&mut signature).map_err(TicketError::IO)?;
        // Maybe this can be read differently?
        let mut padding1 = [0u8; 60];
        buf.read_exact(&mut padding1).map_err(TicketError::IO)?;
        let mut signature_issuer = [0u8; 64];
        buf.read_exact(&mut signature_issuer).map_err(TicketError::IO)?;
        let mut ecdh_data = [0u8; 60];
        buf.read_exact(&mut ecdh_data).map_err(TicketError::IO)?;
        let ticket_version = buf.read_u8().map_err(TicketError::IO)?;
        // v1 Tickets are NOT supported (just like in libWiiPy).
        if ticket_version != 0 {
            return Err(TicketError::UnsupportedVersion(ticket_version));
        }
        let mut reserved1 = [0u8; 2];
        buf.read_exact(&mut reserved1).map_err(TicketError::IO)?;
        let mut title_key = [0u8; 16];
        buf.read_exact(&mut title_key).map_err(TicketError::IO)?;
        let mut unknown1 = [0u8; 1];
        buf.read_exact(&mut unknown1).map_err(TicketError::IO)?;
        let mut ticket_id = [0u8; 8];
        buf.read_exact(&mut ticket_id).map_err(TicketError::IO)?;
        let mut console_id = [0u8; 4];
        buf.read_exact(&mut console_id).map_err(TicketError::IO)?;
        let mut title_id = [0u8; 8];
        buf.read_exact(&mut title_id).map_err(TicketError::IO)?;
        let mut unknown2 = [0u8; 2];
        buf.read_exact(&mut unknown2).map_err(TicketError::IO)?;
        let title_version = buf.read_u16::<BigEndian>().map_err(TicketError::IO)?;
        let mut permitted_titles_mask = [0u8; 4];
        buf.read_exact(&mut permitted_titles_mask).map_err(TicketError::IO)?;
        let mut permit_mask = [0u8; 4];
        buf.read_exact(&mut permit_mask).map_err(TicketError::IO)?;
        let title_export_allowed = buf.read_u8().map_err(TicketError::IO)?;
        let common_key_index = buf.read_u8().map_err(TicketError::IO)?;
        let mut unknown3 = [0u8; 48];
        buf.read_exact(&mut unknown3).map_err(TicketError::IO)?;
        let mut content_access_permission = [0u8; 64];
        buf.read_exact(&mut content_access_permission).map_err(TicketError::IO)?;
        let mut padding2 = [0u8; 2];
        buf.read_exact(&mut padding2).map_err(TicketError::IO)?;
        // Build the array of title limits.
        let mut title_limits: Vec<TitleLimit> = Vec::new();
        for _ in 0..8 {
            let limit_type = buf.read_u32::<BigEndian>().map_err(TicketError::IO)?;
            let limit_max = buf.read_u32::<BigEndian>().map_err(TicketError::IO)?;
            title_limits.push(TitleLimit { limit_type, limit_max });
        }
        let title_limits = title_limits.try_into().unwrap();
        Ok(Ticket {
            signature_type,
            signature,
            padding1,
            signature_issuer,
            ecdh_data,
            ticket_version,
            reserved1,
            title_key,
            unknown1,
            ticket_id,
            console_id,
            title_id,
            unknown2,
            title_version,
            permitted_titles_mask,
            permit_mask,
            title_export_allowed,
            common_key_index,
            unknown3,
            content_access_permission,
            padding2,
            title_limits,
        })
    }

    /// Dumps the data in a Ticket instance back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_u32::<BigEndian>(self.signature_type)?;
        buf.write_all(&self.signature)?;
        buf.write_all(&self.padding1)?;
        buf.write_all(&self.signature_issuer)?;
        buf.write_all(&self.ecdh_data)?;
        buf.write_u8(self.ticket_version)?;
        buf.write_all(&self.reserved1)?;
        buf.write_all(&self.title_key)?;
        buf.write_all(&self.unknown1)?;
        buf.write_all(&self.ticket_id)?;
        buf.write_all(&self.console_id)?;
        buf.write_all(&self.title_id)?;
        buf.write_all(&self.unknown2)?;
        buf.write_u16::<BigEndian>(self.title_version)?;
        buf.write_all(&self.permitted_titles_mask)?;
        buf.write_all(&self.permit_mask)?;
        buf.write_u8(self.title_export_allowed)?;
        buf.write_u8(self.common_key_index)?;
        buf.write_all(&self.unknown3)?;
        buf.write_all(&self.content_access_permission)?;
        buf.write_all(&self.padding2)?;
        // Iterate over title limits and write out their data.
        for limit in &self.title_limits {
            buf.write_u32::<BigEndian>(limit.limit_type)?;
            buf.write_u32::<BigEndian>(limit.limit_max)?;
        }
        Ok(buf)
    }

    /// Gets the type of the signature on the Ticket.
    pub fn signature_type(&self) -> u32 {
        self.signature_type
    }

    /// Gets the signature of the Ticket.
    pub fn signature(&self) -> [u8; 256] {
        self.signature
    }

    /// Gets the ECDH data listed in the Ticket.
    pub fn ecdh_data(&self) -> [u8; 60] {
        self.ecdh_data
    }

    /// Gets the version of the Ticket file.
    pub fn ticket_version(&self) -> u8 {
        self.ticket_version
    }

    /// Gets the raw encrypted Title Key from the Ticket.
    pub fn title_key(&self) -> [u8; 16] {
        self.title_key
    }

    pub fn set_title_key(&mut self, title_key: [u8; 16]) {
        self.title_key = title_key;
    }

    /// Gets the Ticket ID listed in the Ticket.
    pub fn ticket_id(&self) -> [u8; 8] {
        self.ticket_id
    }

    /// Gets the console ID listed in the Ticket.
    pub fn console_id(&self) -> [u8; 4] {
        self.console_id
    }

    /// Gets the version of the title listed in the Ticket.
    pub fn title_version(&self) -> u16 {
        self.title_version
    }
    
    pub fn set_title_version(&mut self, version: u16) {
        self.title_version = version;
    }

    /// Gets the permitted titles mask listed in the Ticket.
    pub fn permitted_titles_mask(&self) -> [u8; 4] {
        self.permitted_titles_mask
    }

    /// Gets the permit mask listed in the Ticket.
    pub fn permit_mask(&self) -> [u8; 4] {
        self.permit_mask
    }

    /// Gets whether title export is allowed by the Ticket.
    pub fn title_export_allowed(&self) -> bool {
        self.title_export_allowed == 1
    }

    /// Gets the index of the common key used by the Ticket.
    pub fn common_key_index(&self) -> u8 {
        self.common_key_index
    }

    /// Sets the index of the common key used by the Ticket.
    pub fn set_common_key_index(&mut self, index: u8) {
        self.common_key_index = index;
    }

    /// Gets the content access permissions listed in the Ticket.
    pub fn content_access_permission(&self) -> [u8; 64] {
        self.content_access_permission
    }

    /// Gets the title usage limits listed in the Ticket.
    pub fn title_limits(&self) -> [TitleLimit; 8] {
        self.title_limits
    }

    /// Gets the decrypted version of the Title Key stored in a Ticket.
    pub fn title_key_dec(&self) -> [u8; 16] {
        // Get the dev status of this Ticket so decrypt_title_key knows the right common key.
        let is_dev = self.is_dev();
        decrypt_title_key(self.title_key, self.common_key_index, self.title_id, is_dev)
    }
    
    /// Gets whether a Ticket was signed for development (true) or retail (false).
    pub fn is_dev(&self) -> bool {
        // Parse the signature issuer to determine if this is a dev Ticket or not.
        let issuer_str = String::from_utf8(Vec::from(&self.signature_issuer)).unwrap_or_default();
        issuer_str.contains("Root-CA00000002-XS00000004") || issuer_str.contains("Root-CA00000002-XS00000006")
    }
    
    /// Gets whether a Ticket is fakesigned using the strncmp (trucha) bug or not.
    pub fn is_fakesigned(&self) -> bool {
        // Can't be fakesigned without a null signature.
        if self.signature != [0; 256] {
            return false;
        }
        // Test the hash of the Ticket body to make sure it starts with 00.
        let mut hasher = Sha1::new();
        let ticket_body = self.to_bytes().unwrap();
        hasher.update(&ticket_body[320..]);
        let result = hasher.finalize();
        if result[0] != 0 {
            return false;
        }
        true
    }
    
    /// Fakesigns a Ticket for use with the strncmp (trucha) bug.
    pub fn fakesign(&mut self) -> Result<(), TicketError> {
        // Erase the signature.
        self.signature = [0; 256];
        let mut current_int: u16 = 0;
        let mut test_hash: [u8; 20] = [255; 20];
        while test_hash[0] != 0 {
            if current_int == 65535 { return Err(TicketError::CannotFakesign); }
            current_int += 1;
            self.unknown2 = current_int.to_be_bytes();
            let mut hasher = Sha1::new();
            let ticket_body = self.to_bytes()?;
            hasher.update(&ticket_body[320..]);
            test_hash = <[u8; 20]>::from(hasher.finalize());
        }
        Ok(())
    }

    /// Gets the name of the certificate used to sign a Ticket as a string.
    pub fn signature_issuer(&self) -> String {
        String::from_utf8_lossy(&self.signature_issuer).trim_end_matches('\0').to_owned()
    }

    /// Sets a new name for the certificate used to sign a Ticket.
    pub fn set_signature_issuer(&mut self, signature_issuer: String) -> Result<(), TicketError> {
        if signature_issuer.len() > 64 {
            return Err(TicketError::IssuerTooLong(signature_issuer.len()));
        }
        let mut issuer = signature_issuer.into_bytes();
        issuer.resize(64, 0);
        self.signature_issuer = issuer.try_into().unwrap();
        Ok(())
    }
    
    /// Gets the Title ID of the Ticket.
    pub fn title_id(&self) -> [u8; 8] {
        self.title_id
    }
    
    /// Sets a new Title ID for the Ticket. This will re-encrypt the Title Key, since the Title ID
    /// is used as the IV for decrypting the Title Key.
    pub fn set_title_id(&mut self, title_id: [u8; 8]) {
        let new_enc_title_key = crypto::encrypt_title_key(self.title_key_dec(), self.common_key_index, title_id, self.is_dev());
        self.title_key = new_enc_title_key;
        self.title_id = title_id;
    }
}
