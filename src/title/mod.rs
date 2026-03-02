// title/mod.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Root for all title-related modules and implementation of the high-level Title object.

pub mod cert;
pub mod commonkeys;
pub mod crypto;
pub mod iospatcher;
pub mod nus;
pub mod ticket;
pub mod tmd;
pub mod versions;
pub mod wad;

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use sha1::{Sha1, Digest};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TitleError {
    #[error("the data for required Title component `{0}` was invalid")]
    InvalidData(String),
    #[error("WAD data is not in a valid format")]
    InvalidWAD,
    #[error("certificate processing error")]
    CertificateError(#[from] cert::CertificateError),
    #[error("TMD processing error")]
    TMD(#[from] tmd::TMDError),
    #[error("Ticket processing error")]
    Ticket(#[from] ticket::TicketError),
    #[error("WAD processing error")]
    WAD(#[from] wad::WADError),
    #[error("WAD data is not in a valid format")]
    IO(#[from] std::io::Error),
    // Content-specific (not generic or inherited from another struct's errors).
    #[error("requested index {index} is out of range (must not exceed {max})")]
    IndexOutOfRange { index: usize, max: usize },
    #[error("expected {required} contents based on content records but found {found}")]
    MissingContents { required: usize, found: usize },
    #[error("content with requested Content ID {0} could not be found")]
    CIDNotFound(u32),
    #[error("the specified index {0} already exists in the content records")]
    IndexAlreadyExists(u16),
    #[error("the specified Content ID {0} already exists in the content records")]
    CIDAlreadyExists(u32),
    #[error("content's hash did not match the expected value (was {hash}, expected {expected})")]
    BadHash { hash: String, expected: String },
}

#[derive(Debug)]
/// A structure that represents the components of a digital Wii title.
pub struct Title {
    cert_chain: cert::CertificateChain,
    crl: Vec<u8>,
    ticket: ticket::Ticket,
    tmd: tmd::TMD,
    content: Vec<Vec<u8>>,
    meta: Vec<u8>
}

impl Title {
    /// Creates a new Title instance from an existing WAD instance.
    pub fn from_wad(wad: &wad::WAD) -> Result<Title, TitleError> {
        let cert_chain = cert::CertificateChain::from_bytes(&wad.cert_chain()).map_err(TitleError::CertificateError)?;
        let ticket = ticket::Ticket::from_bytes(&wad.ticket()).map_err(TitleError::Ticket)?;
        let tmd = tmd::TMD::from_bytes(&wad.tmd()).map_err(TitleError::TMD)?;
        let content = Self::parse_content_region(wad.content(), tmd.content_records())?;
        Ok(Title {
            cert_chain,
            crl: wad.crl(),
            ticket,
            tmd,
            content,
            meta: wad.meta(),
        })
    }
    
    /// Creates a new Title instance from all of its individual components.
    pub fn from_parts_with_content(
        cert_chain: cert::CertificateChain,
        crl: Option<&[u8]>,
        ticket: ticket::Ticket,
        tmd: tmd::TMD,
        content: Vec<Vec<u8>>,
        meta: Option<&[u8]>
    ) -> Result<Title, TitleError> {
        // Validate the provided content.
        if content.len() != tmd.content_records().len() {
            return Err(TitleError::MissingContents { required: tmd.content_records().len(), found: content.len()});
        }
        // Create empty vecs for the CRL and meta areas if we weren't supplied with any, as they're
        // optional components.
        let crl = match crl {
            Some(crl) => crl.to_vec(),
            None => Vec::new()
        };
        let meta = match meta {
            Some(meta) => meta.to_vec(),
            None => Vec::new()
        };
        Ok(Title {
            cert_chain,
            crl,
            ticket,
            tmd,
            content,
            meta
        })
    }

    /// Creates a new Title instance from all of its individual components. Content is expected to
    /// be added to the title once created.
    pub fn from_parts(
        cert_chain: cert::CertificateChain,
        crl: Option<&[u8]>,
        ticket: ticket::Ticket,
        tmd: tmd::TMD,
        meta: Option<&[u8]>
    ) -> Result<Title, TitleError> {
        let content: Vec<Vec<u8>> = vec![vec![]; tmd.content_records().len()];
        Self::from_parts_with_content(
            cert_chain,
            crl,
            ticket,
            tmd,
            content,
            meta
        )
    }

    fn parse_content_region(content_data: Vec<u8>, content_records: &[tmd::ContentRecord]) -> Result<Vec<Vec<u8>>, TitleError> {
        let num_contents = content_records.len();
        // Calculate the starting offsets of each content.
        let content_start_offsets: Vec<u64> = std::iter::once(0)
            .chain(content_records.iter().scan(0, |offset, record| {
                *offset += record.content_size;
                if record.content_size % 64 != 0 {
                    *offset += 64 - (record.content_size % 64);
                }
                Some(*offset)
            })).take(content_records.len()).collect(); // Trims the extra final entry.
        // Parse the content blob and create a vector of vectors from it.
        let mut contents: Vec<Vec<u8>> = Vec::with_capacity(num_contents);
        let mut buf = Cursor::new(content_data);
        for i in 0..num_contents {
            buf.seek(SeekFrom::Start(content_start_offsets[i]))?;
            let size = (content_records[i].content_size + 15) & !15;
            let mut content = vec![0u8; size as usize];
            buf.read_exact(&mut content)?;
            contents.push(content);
        }

        Ok(contents)
    }
    
    /// Converts a Title instance into a WAD, which can be used to export the Title back to a file.
    pub fn to_wad(&self) -> Result<wad::WAD, TitleError> {
        let mut content: Vec<u8> = Vec::new();
        for i in 0..self.tmd.content_records().len() {
            let mut content_cur = self.content[i].clone();
            // Round up size to nearest 64 to add appropriate padding.
            content_cur.resize((content_cur.len() + 63) & !63, 0);
            content.write_all(&content_cur)?;
        }
        // Create a new WAD from the data in the Title.
        let wad = wad::WAD::from_parts(
            &self.cert_chain,
            &self.crl,
            &self.ticket,
            &self.tmd,
            &content,
            &self.meta
        ).map_err(TitleError::WAD)?;
        Ok(wad)
    }
    
    /// Creates a new Title instance from the binary data of a WAD file.
    pub fn from_bytes(bytes: &[u8]) -> Result<Title, TitleError> {
        let wad = wad::WAD::from_bytes(bytes).map_err(|_| TitleError::InvalidWAD)?;
        let title = Title::from_wad(&wad)?;
        Ok(title)
    }

    pub fn cert_chain(&self) -> &cert::CertificateChain {
        &self.cert_chain
    }

    pub fn ticket(&self) -> &ticket::Ticket {
        &self.ticket
    }

    pub fn tmd(&self) -> &tmd::TMD {
        &self.tmd
    }
    
    /// Gets whether the TMD and Ticket of a Title are both fakesigned.
    pub fn is_fakesigned(&self) -> bool {
        self.tmd.is_fakesigned() && self.ticket.is_fakesigned()
    }
    
    /// Fakesigns the TMD and Ticket of a Title.
    pub fn fakesign(&mut self) -> Result<(), TitleError> {
        // Run the fakesign methods on the TMD and Ticket.
        self.tmd.fakesign().map_err(TitleError::TMD)?;
        self.ticket.fakesign().map_err(TitleError::Ticket)?;
        Ok(())
    }

    /// Gets the encrypted content file from the ContentRegion at the specified index.
    pub fn get_enc_content_by_index(&self, index: usize) -> Result<Vec<u8>, TitleError> {
        let content = self.content.get(index).ok_or(
            TitleError::IndexOutOfRange { index, max: self.tmd.content_records().len() - 1 }
        )?;
        Ok(content.clone())
    }

    /// Gets the decrypted content file from the Title at the specified index.
    pub fn get_content_by_index(&self, index: usize) -> Result<Vec<u8>, TitleError> {
        let content = self.get_enc_content_by_index(index)?;
        // Verify the hash of the decrypted content against its record.
        let mut content_dec = crypto::decrypt_content(&content, self.ticket.title_key_dec(), self.tmd.content_records()[index].index);
        content_dec.resize(self.tmd.content_records()[index].content_size as usize, 0);
        let mut hasher = Sha1::new();
        hasher.update(content_dec.clone());
        let result = hasher.finalize();
        if result[..] != self.tmd.content_records()[index].content_hash {
            return Err(TitleError::BadHash {
                hash: hex::encode(result), expected: hex::encode(self.tmd.content_records()[index].content_hash)
            });
        }
        Ok(content_dec)
    }

    /// Gets the encrypted content file from the ContentRegion with the specified Content ID.
    pub fn get_enc_content_by_cid(&self, cid: u32) -> Result<Vec<u8>, TitleError> {
        let index = self.tmd.content_records().iter().position(|x| x.content_id == cid);
        if let Some(index) = index {
            let content = self.get_enc_content_by_index(index).map_err(|_| TitleError::CIDNotFound(cid))?;
            Ok(content)
        } else {
            Err(TitleError::CIDNotFound(cid))
        }
    }
    
    /// Gets the decrypted content file from the Title with the specified Content ID.
    pub fn get_content_by_cid(&self, cid: u32) -> Result<Vec<u8>, TitleError> {
        let index = self.tmd.content_records().iter().position(|x| x.content_id == cid);
        if let Some(index) = index {
            let content_dec = self.get_content_by_index(index)?;
            Ok(content_dec)
        } else {
            Err(TitleError::CIDNotFound(cid))
        }
    }

    /// Loads existing content into the specified index of a ContentRegion instance. This content
    /// must be encrypted.
    pub fn load_enc_content(&mut self, content: &[u8], index: usize) -> Result<(), TitleError> {
        if index >= self.tmd.content_records().len() {
            return Err(TitleError::IndexOutOfRange { index, max: self.tmd.content_records().len() - 1 });
        }
        self.content[index] = content.to_vec();
        Ok(())
    }

    /// Sets the content at the specified index to the provided encrypted content. This requires
    /// the size and hash of the original decrypted content to be known so that the appropriate
    /// values can be set in the corresponding content record. Optionally, a new Content ID or
    /// content type can be provided, with the existing values being preserved by default.
    pub fn set_enc_content(
        &mut self, content: &[u8],
        index: usize, content_size: u64,
        content_hash: [u8; 20],
        cid: Option<u32>,
        content_type: Option<tmd::ContentType>
    ) -> Result<(), TitleError> {
        if index >= self.tmd.content_records().len() {
            return Err(TitleError::IndexOutOfRange { index, max: self.tmd.content_records().len() - 1 });
        }
        let mut content_records = self.tmd.content_records().clone();
        content_records[index].content_size = content_size;
        content_records[index].content_hash = content_hash;
        if let Some(cid) = cid {
            // Make sure that the new CID isn't already in use.
            if content_records.iter().any(|record| record.content_id == cid) {
                return Err(TitleError::CIDAlreadyExists(cid));
            }
            content_records[index].content_id = cid;
        }
        if let Some(content_type) = content_type {
            content_records[index].content_type = content_type;
        }
        self.tmd.set_content_records(content_records);
        self.content[index] = content.to_vec();
        Ok(())
    }

    /// Loads existing content into the specified index of a ContentRegion instance. This content
    /// must be decrypted and needs to match the size and hash listed in the content record at that
    /// index.
    pub fn load_content(&mut self, content: &[u8], index: usize) -> Result<(), TitleError> {
        if index >= self.tmd.content_records().len() {
            return Err(TitleError::IndexOutOfRange { index, max: self.tmd.content_records().len() - 1 });
        }
        // Hash the content we're trying to load to ensure it matches the hash expected in the
        // matching record.
        let mut hasher = Sha1::new();
        hasher.update(content);
        let result = hasher.finalize();
        if result[..] != self.tmd.content_records()[index].content_hash {
            return Err(TitleError::BadHash {
                hash: hex::encode(result), expected: hex::encode(self.tmd.content_records()[index].content_hash)
            });
        }
        let content_enc = crypto::encrypt_content(
            content,
            self.ticket.title_key_dec(),
            self.tmd.content_records()[index].index,
            self.tmd.content_records()[index].content_size
        );
        self.content[index] = content_enc;
        Ok(())
    }

    /// Sets the content at the specified index to the provided decrypted content. This content will
    /// have its size and hash saved into the matching record. Optionally, a new Content ID or
    /// content type can be provided, with the existing values being preserved by default.
    pub fn set_content(&mut self, content: &[u8], index: usize, cid: Option<u32>, content_type: Option<tmd::ContentType>) -> Result<(), TitleError> {
        let content_size = content.len() as u64;
        let mut hasher = Sha1::new();
        hasher.update(content);
        let content_hash: [u8; 20] = hasher.finalize().into();
        let content_enc = crypto::encrypt_content(
            content,
            self.ticket.title_key_dec(),
            index as u16,
            content_size
        );
        self.set_enc_content(&content_enc, index, content_size, content_hash, cid, content_type)?;
        Ok(())
    }

    /// Removes the content at the specified index from the content list and content records. This
    /// may leave a gap in the indexes recorded in the content records, but this should not cause
    /// issues on the Wii or with correctly implemented WAD parsers.
    pub fn remove_content(&mut self, index: usize) -> Result<(), TitleError> {
        if self.content.get(index).is_none() || self.tmd.content_records().get(index).is_none() {
            return Err(TitleError::IndexOutOfRange { index, max: self.tmd.content_records().len() - 1 });
        }
        self.content.remove(index);
        let mut content_records = self.tmd.content_records().clone();
        content_records.remove(index);
        self.tmd.set_content_records(content_records);
        Ok(())
    }

    /// Adds new encrypted content to the end of the content list and content records. The provided
    /// Content ID, type, index, and decrypted hash will be added to the record.
    pub fn add_enc_content(
        &mut self, content:
        &[u8], index: u16,
        cid: u32,
        content_type: tmd::ContentType,
        content_size: u64,
        content_hash: [u8; 20]
    ) -> Result<(), TitleError> {
        // Return an error if the specified index or CID already exist in the records.
        if self.tmd.content_records().iter().any(|record| record.index == index) {
            return Err(TitleError::IndexAlreadyExists(index));
        }
        if self.tmd.content_records().iter().any(|record| record.content_id == cid) {
            return Err(TitleError::CIDAlreadyExists(cid));
        }
        self.content.push(content.to_vec());
        let mut content_records = self.tmd.content_records().clone();
        content_records.push(tmd::ContentRecord { content_id: cid, index, content_type, content_size, content_hash });
        self.tmd.set_content_records(content_records);
        Ok(())
    }

    /// Adds new decrypted content to the end of the content list and content records. The provided
    /// Content ID and type will be added to the record alongside a hash of the decrypted data. An
    /// index will be automatically assigned based on the highest index currently recorded in the
    /// content records.
    pub fn add_content(&mut self, content: &[u8], cid: u32, content_type: tmd::ContentType) -> Result<(), TitleError> {
        let max_index = self.tmd.content_records().iter()
            .max_by_key(|record| record.index)
            .map(|record| record.index)
            .unwrap_or(0); // This should be impossible, but I guess 0 is a safe value just in case?
        let new_index = max_index + 1;
        let content_size = content.len() as u64;
        let mut hasher = Sha1::new();
        hasher.update(content);
        let content_hash: [u8; 20] = hasher.finalize().into();
        let content_enc = crypto::encrypt_content(content, self.ticket.title_key_dec(), new_index, content_size);
        self.add_enc_content(&content_enc, new_index, cid, content_type, content_size, content_hash)?;
        Ok(())
    }
    
    /// Gets the installed size of the title, in bytes. Use the optional parameter "absolute" to set
    /// whether shared content should be included in this total or not.
    pub fn title_size(&self, absolute: Option<bool>) -> Result<usize, TitleError> {
        let mut title_size: usize = 0;
        // Get the TMD and Ticket size by dumping them and measuring their length for the most
        // accurate results.
        title_size += self.tmd.to_bytes().map_err(|x| TitleError::TMD(tmd::TMDError::IO(x)))?.len();
        title_size += self.ticket.to_bytes().map_err(|x| TitleError::Ticket(ticket::TicketError::IO(x)))?.len();
        for record in self.tmd.content_records().iter() {
            if matches!(record.content_type, tmd::ContentType::Shared) {
                if absolute == Some(true) {
                    title_size += record.content_size as usize;
                }
            }
            else {
                title_size += record.content_size as usize;
            }
        }
        Ok(title_size)
    }
    
    /// Verifies entire certificate chain, and then the TMD and Ticket. Returns true if the title
    /// is entirely valid, or false if any component of the verification fails.
    pub fn verify(&self) -> Result<bool, TitleError> {
        if !cert::verify_ca_cert(&self.cert_chain.ca_cert()).map_err(TitleError::CertificateError)? {
            return Ok(false)
        }
        if !cert::verify_child_cert(&self.cert_chain.ca_cert(), &self.cert_chain.tmd_cert()).map_err(TitleError::CertificateError)? ||
            !cert::verify_child_cert(&self.cert_chain.ca_cert(), &self.cert_chain.ticket_cert()).map_err(TitleError::CertificateError)? {
            return Ok(false)
        }
        if !cert::verify_tmd(&self.cert_chain.tmd_cert(), &self.tmd).map_err(TitleError::CertificateError)? ||
            !cert::verify_ticket(&self.cert_chain.ticket_cert(), &self.ticket).map_err(TitleError::CertificateError)? {
            return Ok(false)
        }
        Ok(true)
    }
    
    /// Sets a new Title ID for the Title. This will re-encrypt the Title Key in the Ticket, since 
    /// the Title ID is used as the IV for decrypting the Title Key.
    pub fn set_title_id(&mut self, title_id: [u8; 8]) -> Result<(), TitleError> {
        self.tmd.set_title_id(title_id);
        self.ticket.set_title_id(title_id);
        Ok(())
    }

    pub fn set_title_version(&mut self, version: u16) {
        self.tmd.set_title_version(version);
        self.ticket.set_title_version(version);
    }

    pub fn set_cert_chain(&mut self, cert_chain: cert::CertificateChain) {
        self.cert_chain = cert_chain;
    }
    
    pub fn crl(&self) -> Vec<u8> {
        self.crl.clone()
    }
    
    pub fn set_crl(&mut self, crl: &[u8]) {
        self.crl = crl.to_vec();
    }
    
    pub fn set_ticket(&mut self, ticket: ticket::Ticket) {
        self.ticket = ticket;
    }
    
    pub fn set_tmd(&mut self, tmd: tmd::TMD) {
        self.tmd = tmd;
    }
    
    pub fn set_contents(&mut self, content: Vec<Vec<u8>>) {
        self.content = content;
    }
    
    pub fn meta(&self) -> Vec<u8> {
        self.meta.clone()
    }
    
    pub fn set_meta(&mut self, meta: &[u8]) {
        self.meta = meta.to_vec();
    }
}

/// Converts bytes to the Wii's storage unit, blocks.
pub fn bytes_to_blocks(size_bytes: usize) -> usize {
    (size_bytes as f64 / 131072.0).ceil() as usize
}
