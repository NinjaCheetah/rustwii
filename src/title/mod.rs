// title/mod.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Root for all title-related modules and implementation of the high-level Title object.

pub mod cert;
pub mod commonkeys;
pub mod content;
pub mod crypto;
pub mod iospatcher;
pub mod nus;
pub mod ticket;
pub mod tmd;
pub mod versions;
pub mod wad;

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
    #[error("content processing error")]
    Content(#[from] content::ContentError),
    #[error("WAD processing error")]
    WAD(#[from] wad::WADError),
    #[error("WAD data is not in a valid format")]
    IO(#[from] std::io::Error),
}

#[derive(Debug)]
/// A structure that represents the components of a digital Wii title.
pub struct Title {
    pub cert_chain: cert::CertificateChain,
    crl: Vec<u8>,
    pub ticket: ticket::Ticket,
    pub tmd: tmd::TMD,
    pub content: content::ContentRegion,
    meta: Vec<u8>
}

impl Title {
    /// Creates a new Title instance from an existing WAD instance.
    pub fn from_wad(wad: &wad::WAD) -> Result<Title, TitleError> {
        let cert_chain = cert::CertificateChain::from_bytes(&wad.cert_chain()).map_err(TitleError::CertificateError)?;
        let ticket = ticket::Ticket::from_bytes(&wad.ticket()).map_err(TitleError::Ticket)?;
        let tmd = tmd::TMD::from_bytes(&wad.tmd()).map_err(TitleError::TMD)?;
        let content = content::ContentRegion::from_bytes(&wad.content(), tmd.content_records().clone()).map_err(TitleError::Content)?;
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
    pub fn from_parts(cert_chain: cert::CertificateChain, crl: Option<&[u8]>, ticket: ticket::Ticket, tmd: tmd::TMD,
                      content: content::ContentRegion, meta: Option<&[u8]>) -> Result<Title, TitleError> {
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
    
    /// Converts a Title instance into a WAD, which can be used to export the Title back to a file.
    pub fn to_wad(&self) -> Result<wad::WAD, TitleError> {
        // Create a new WAD from the data in the Title.
        let wad = wad::WAD::from_parts(
            &self.cert_chain,
            &self.crl,
            &self.ticket,
            &self.tmd,
            &self.content,
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
    
    /// Gets the decrypted content file from the Title at the specified index.
    pub fn get_content_by_index(&self, index: usize) -> Result<Vec<u8>, content::ContentError> {
        let content = self.content.get_content_by_index(index, self.ticket.title_key_dec())?;
        Ok(content)
    }
    
    /// Gets the decrypted content file from the Title with the specified Content ID.
    pub fn get_content_by_cid(&self, cid: u32) -> Result<Vec<u8>, content::ContentError> {
        let content = self.content.get_content_by_cid(cid, self.ticket.title_key_dec())?;
        Ok(content)
    }

    /// Sets the content at the specified index to the provided decrypted content. This content will
    /// have its size and hash saved into the matching record. Optionally, a new Content ID or
    /// content type can be provided, with the existing values being preserved by default.
    pub fn set_content(&mut self, content: &[u8], index: usize, cid: Option<u32>, content_type: Option<tmd::ContentType>) -> Result<(), TitleError> {
        self.content.set_content(content, index, cid, content_type, self.ticket.title_key_dec())?;
        self.tmd.set_content_records(self.content.content_records());
        Ok(())
    }

    /// Adds new decrypted content to the end of the content list and content records. The provided
    /// Content ID and type will be added to the record alongside a hash of the decrypted data. An
    /// index will be automatically assigned based on the highest index currently recorded in the
    /// content records.
    pub fn add_content(&mut self, content: &[u8], cid: u32, content_type: tmd::ContentType) -> Result<(), TitleError> {
        self.content.add_content(content, cid, content_type, self.ticket.title_key_dec())?;
        self.tmd.set_content_records(self.content.content_records());
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
    
    pub fn set_content_region(&mut self, content: content::ContentRegion) {
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
