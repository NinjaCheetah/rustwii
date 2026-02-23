// title/cert.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for validating the signatures of Wii titles.

use std::io::{Cursor, Read, Write, SeekFrom, Seek};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rsa::pkcs8::DecodePublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{RsaPublicKey, BigUint};
use sha1::{Digest, Sha1};
use thiserror::Error;
use crate::title::{tmd, ticket};

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("certificate appears to be signed with invalid key type `{0}`")]
    InvalidSignatureKeyType(u32),
    #[error("certificate appears to contain key with invalid type `{0}`")]
    InvalidContainedKeyType(u32),
    #[error("certificate chain contains an unknown certificate")]
    UnknownCertificate,
    #[error("certificate chain is missing required certificate `{0}`")]
    MissingCertificate(String),
    #[error("attempted to load incorrect certificate `{0}`")]
    IncorrectCertificate(String),
    #[error("the data you are attempting to verify was not signed with the provided certificate")]
    NonMatchingCertificates,
    #[error("certificate data is not in a valid format")]
    IO(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub enum CertificateKeyType {
    Rsa4096,
    Rsa2048,
    ECC
}

/// A structure that represents the components of a Wii signing certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    signer_key_type: CertificateKeyType,
    signature: Vec<u8>,
    signature_issuer: [u8; 64],
    pub_key_type: CertificateKeyType,
    child_cert_identity: [u8; 64],
    pub_key_id: u32,
    pub_key_modulus: Vec<u8>,
    pub_key_exponent: u32
}

impl Certificate {
    /// Creates a new Certificate instance from the binary data of a certificate file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CertificateError> {
        let mut buf = Cursor::new(data);
        let signer_key_type_int = buf.read_u32::<BigEndian>().map_err(CertificateError::IO)?;
        let signer_key_type = match signer_key_type_int {
            0x00010000 => CertificateKeyType::Rsa4096,
            0x00010001 => CertificateKeyType::Rsa2048,
            0x00010002 => CertificateKeyType::ECC,
            _ => return Err(CertificateError::InvalidSignatureKeyType(signer_key_type_int))
        };
        let signature_len = match signer_key_type {
            CertificateKeyType::Rsa4096 => 512,
            CertificateKeyType::Rsa2048 => 256,
            CertificateKeyType::ECC => 60,
        };
        let mut signature = vec![0u8; signature_len];
        buf.read_exact(&mut signature).map_err(CertificateError::IO)?;
        // Skip past padding at the end of the signature.
        buf.seek(SeekFrom::Start(0x40 + signature_len as u64)).map_err(CertificateError::IO)?;
        let mut signature_issuer = [0u8; 64];
        buf.read_exact(&mut signature_issuer).map_err(CertificateError::IO)?;
        let pub_key_type_int = buf.read_u32::<BigEndian>().map_err(CertificateError::IO)?;
        let pub_key_type = match pub_key_type_int {
            0x00000000 => CertificateKeyType::Rsa4096,
            0x00000001 => CertificateKeyType::Rsa2048,
            0x00000002 => CertificateKeyType::ECC,
            _ => return Err(CertificateError::InvalidContainedKeyType(pub_key_type_int))
        };
        let mut child_cert_identity = [0u8; 64];
        buf.read_exact(&mut child_cert_identity).map_err(CertificateError::IO)?;
        let pub_key_id = buf.read_u32::<BigEndian>().map_err(CertificateError::IO)?;
        let mut pub_key_modulus: Vec<u8>;
        let mut pub_key_exponent: u32 = 0;
        // The key size and exponent are different based on the key type. ECC has no exponent.
        match pub_key_type {
            CertificateKeyType::Rsa4096 => {
                pub_key_modulus = vec![0u8; 512];
                buf.read_exact(&mut pub_key_modulus).map_err(CertificateError::IO)?;
                pub_key_exponent = buf.read_u32::<BigEndian>().map_err(CertificateError::IO)?;
            },
            CertificateKeyType::Rsa2048 => {
                pub_key_modulus = vec![0u8; 256];
                buf.read_exact(&mut pub_key_modulus).map_err(CertificateError::IO)?;
                pub_key_exponent = buf.read_u32::<BigEndian>().map_err(CertificateError::IO)?;
            },
            CertificateKeyType::ECC => {
                pub_key_modulus = vec![0u8; 60];
                buf.read_exact(&mut pub_key_modulus).map_err(CertificateError::IO)?;
            }
        }
        Ok(Certificate {
            signer_key_type,
            signature,
            signature_issuer,
            pub_key_type,
            child_cert_identity,
            pub_key_id,
            pub_key_modulus,
            pub_key_exponent
        })
    }

    /// Dumps the data in a Certificate instance back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        match self.signer_key_type {
            CertificateKeyType::Rsa4096 => { buf.write_u32::<BigEndian>(0x00010000)? },
            CertificateKeyType::Rsa2048 => { buf.write_u32::<BigEndian>(0x00010001)? },
            CertificateKeyType::ECC => { buf.write_u32::<BigEndian>(0x00010002)? },
        }
        buf.write_all(&self.signature)?;
        // Pad to nearest 64 bytes after the signature.
        buf.resize(0x40 + self.signature.len(), 0);
        buf.write_all(&self.signature_issuer)?;
        match self.pub_key_type {
            CertificateKeyType::Rsa4096 => { buf.write_u32::<BigEndian>(0x0000000)? },
            CertificateKeyType::Rsa2048 => { buf.write_u32::<BigEndian>(0x00000001)? },
            CertificateKeyType::ECC => { buf.write_u32::<BigEndian>(0x00000002)? },
        }
        buf.write_all(&self.child_cert_identity)?;
        buf.write_u32::<BigEndian>(self.pub_key_id)?;
        buf.write_all(&self.pub_key_modulus)?;
        // The key exponent is only used for the RSA keys and not ECC keys, so only write it out
        // if this is one of those two key types.
        if matches!(self.pub_key_type, CertificateKeyType::Rsa4096) ||
            matches!(self.pub_key_type, CertificateKeyType::Rsa2048) {
            buf.write_u32::<BigEndian>(self.pub_key_exponent)?;
        }
        // Pad the certificate data out to the nearest multiple of 64.
        buf.resize((buf.len() + 63) & !63, 0);
        Ok(buf)
    }
    
    /// Gets the name of the certificate used to sign a certificate as a string.
    pub fn signature_issuer(&self) -> String {
        String::from_utf8_lossy(&self.signature_issuer).trim_end_matches('\0').to_owned()
    }
    
    /// Gets the name of a certificate's child certificate as a string.
    pub fn child_cert_identity(&self) -> String {
        String::from_utf8_lossy(&self.child_cert_identity).trim_end_matches('\0').to_owned()
    }
    
    /// Gets the modulus of the public key contained in a certificate.
    pub fn pub_key_modulus(&self) -> Vec<u8> {
        self.pub_key_modulus.clone()
    }
    
    /// Gets the exponent of the public key contained in a certificate.
    pub fn pub_key_exponent(&self) -> u32 {
        self.pub_key_exponent
    }
}

/// A structure that represents the components of the Wii's signing certificate chain.
#[derive(Debug)]
pub struct CertificateChain {
    ca_cert: Certificate,
    tmd_cert: Certificate,
    ticket_cert: Certificate,
}

impl CertificateChain {
    /// Creates a new CertificateChain instance from the binary data of an entire certificate chain.
    /// This chain must contain a CA certificate, a TMD certificate, and a Ticket certificate or
    /// else this method will return an error.
    pub fn from_bytes(data: &[u8]) -> Result<CertificateChain, CertificateError> {
        let mut buf = Cursor::new(data);
        let mut offset: u64 = 0;
        let mut ca_cert: Option<Certificate> = None;
        let mut tmd_cert: Option<Certificate> = None;
        let mut ticket_cert: Option<Certificate> = None;
        // Iterate 3 times, because the chain should contain 3 certs.
        for _ in 0..3 {
            buf.seek(SeekFrom::Start(offset)).map_err(CertificateError::IO)?;
            let signer_key_type = buf.read_u32::<BigEndian>().map_err(CertificateError::IO)?;
            let signature_len = match signer_key_type {
                0x00010000 => 512, // 0x200
                0x00010001 => 256, // 0x100
                0x00010002 => 60,
                _ => return Err(CertificateError::InvalidSignatureKeyType(signer_key_type))
            };
            buf.seek(SeekFrom::Start(offset + 0x80 + signature_len)).map_err(CertificateError::IO)?;
            let pub_key_type = buf.read_u32::<BigEndian>().map_err(CertificateError::IO)?;
            let pub_key_len = match pub_key_type {
                0x00000000 => 568, // 0x238
                0x00000001 => 312, // 0x138
                0x00000002 => 120,
                _ => return Err(CertificateError::InvalidContainedKeyType(pub_key_type))
            };
            // Cert size is the base length (0xC8) + the signature length + the public key length.
            // Like a lot of values, it needs to be rounded to the nearest multiple of 64.
            let cert_size = (0xC8 + signature_len + pub_key_len + 63) & !63;
            buf.seek(SeekFrom::End(0)).map_err(CertificateError::IO)?;
            buf.seek(SeekFrom::Start(offset)).map_err(CertificateError::IO)?;
            let mut cert_buf = vec![0u8; cert_size as usize];
            buf.read_exact(&mut cert_buf).map_err(CertificateError::IO)?;
            let cert = Certificate::from_bytes(&cert_buf)?;
            let issuer_name = String::from_utf8_lossy(&cert.signature_issuer).trim_end_matches('\0').to_owned();
            if issuer_name.eq("Root") {
                ca_cert = Some(cert.clone());
            } else if issuer_name.contains("Root-CA") {
                let child_name = String::from_utf8_lossy(&cert.child_cert_identity).trim_end_matches('\0').to_owned();
                if child_name.contains("CP") {
                    tmd_cert = Some(cert.clone());
                } else if child_name.contains("XS") {
                    ticket_cert = Some(cert.clone());
                } else {
                    return Err(CertificateError::UnknownCertificate);
                }
            } else {
                return Err(CertificateError::UnknownCertificate);
            }
            offset += cert_size;
        }
        if ca_cert.is_none() { return Err(CertificateError::MissingCertificate("CA".to_owned())) }
        if tmd_cert.is_none() { return Err(CertificateError::MissingCertificate("TMD".to_owned())) }
        if ticket_cert.is_none() { return Err(CertificateError::MissingCertificate("Ticket".to_owned())) }
        Ok(CertificateChain {
            ca_cert: ca_cert.unwrap(),
            tmd_cert: tmd_cert.unwrap(),
            ticket_cert: ticket_cert.unwrap(),
        })
    }

    /// Creates a new CertificateChain instance from three separate Certificate instances each
    /// containing one of the three certificates stored in the chain. You must provide a CA
    /// certificate, a TMD certificate, and a Ticket certificate, or this method will return an
    /// error.
    pub fn from_certs(ca_cert: Certificate, tmd_cert: Certificate, ticket_cert: Certificate) -> Result<Self, CertificateError> {
        if String::from_utf8_lossy(&ca_cert.signature_issuer).trim_end_matches('\0').ne("Root") {
            return Err(CertificateError::IncorrectCertificate("CA".to_owned()));
        }
        if !String::from_utf8_lossy(&tmd_cert.child_cert_identity).trim_end_matches('\0').contains("CP") {
            return Err(CertificateError::IncorrectCertificate("TMD".to_owned()));
        }
        if !String::from_utf8_lossy(&ticket_cert.child_cert_identity).contains("XS") {
            return Err(CertificateError::IncorrectCertificate("Ticket".to_owned()));
        }
        Ok(CertificateChain {
            ca_cert,
            tmd_cert,
            ticket_cert,
        })
    }
    
    /// Dumps the entire CertificateChain back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_all(&self.ca_cert().to_bytes()?)?;
        buf.write_all(&self.tmd_cert().to_bytes()?)?;
        buf.write_all(&self.ticket_cert().to_bytes()?)?;
        Ok(buf)
    }
    
    pub fn ca_cert(&self) -> Certificate {
        self.ca_cert.clone()
    }
    
    pub fn tmd_cert(&self) -> Certificate {
        self.tmd_cert.clone()
    }
    
    pub fn ticket_cert(&self) -> Certificate {
        self.ticket_cert.clone()
    }
}

/// Verifies a Wii CA certificate (either CA00000001 for retail or CA00000002 for development) using
/// the root keys.
pub fn verify_ca_cert(ca_cert: &Certificate) -> Result<bool, CertificateError> {
    // Reject if the issuer isn't "Root" and this isn't one of the CA certs.
    if String::from_utf8_lossy(&ca_cert.signature_issuer).trim_end_matches('\0').ne("Root") ||
        !String::from_utf8_lossy(&ca_cert.child_cert_identity).contains("CA") {
        return Err(CertificateError::IncorrectCertificate("CA".to_owned()));
    }
    let root_key = if String::from_utf8_lossy(&ca_cert.child_cert_identity).trim_end_matches('\0').eq("CA00000001") {
        // Include key str from local file.
        let retail_pem = include_str!("keys/retail-pub.pem");
        RsaPublicKey::from_public_key_pem(retail_pem).unwrap()
    } else if String::from_utf8_lossy(&ca_cert.child_cert_identity).trim_end_matches('\0').eq("CA00000002") {
        // Include key str from local file.
        let dev_pem = include_str!("keys/dev-pub.pem");
        RsaPublicKey::from_public_key_pem(dev_pem).unwrap()
    } else {
        return Err(CertificateError::UnknownCertificate);
    };
    let mut hasher = Sha1::new();
    let cert_body = ca_cert.to_bytes()?;
    hasher.update(&cert_body[576..]);
    let cert_hash = hasher.finalize().as_slice().to_owned();
    match root_key.verify(Pkcs1v15Sign::new::<Sha1>(), &cert_hash, ca_cert.signature.as_slice()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verifies a TMD or Ticket signing certificate using a CA certificate. The CA certificate and
/// child certificate being verified must match, or this function will return an error without
/// attempting signature verification.
pub fn verify_child_cert(ca_cert: &Certificate, child_cert: &Certificate) -> Result<bool, CertificateError> {
    if ca_cert.signature_issuer().ne("Root") || !ca_cert.child_cert_identity().contains("CA") {
        return Err(CertificateError::IncorrectCertificate("CA".to_owned()));
    }
    if format!("Root-{}", ca_cert.child_cert_identity()).ne(&child_cert.signature_issuer()) {
        return Err(CertificateError::NonMatchingCertificates)
    }
    let mut hasher = Sha1::new();
    hasher.update(&child_cert.to_bytes().map_err(CertificateError::IO)?[320..]);
    let cert_hash = hasher.finalize().as_slice().to_owned();
    let public_key_modulus = BigUint::from_bytes_be(&ca_cert.pub_key_modulus());
    let public_key_exponent = BigUint::from(ca_cert.pub_key_exponent());
    let root_key = RsaPublicKey::new(public_key_modulus, public_key_exponent).unwrap();
    match root_key.verify(Pkcs1v15Sign::new::<Sha1>(), &cert_hash, child_cert.signature.as_slice()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verifies the signature of a TMD using a TMD signing certificate. The TMD certificate must match
/// the certificate used to sign the TMD, or this function will return an error without attempting
/// signature verification.
pub fn verify_tmd(tmd_cert: &Certificate, tmd: &tmd::TMD) -> Result<bool, CertificateError> {
    if !tmd_cert.signature_issuer().contains("Root-CA") || !tmd_cert.child_cert_identity().contains("CP") {
        return Err(CertificateError::IncorrectCertificate("TMD".to_owned()));
    }
    if format!("{}-{}", tmd_cert.signature_issuer(), tmd_cert.child_cert_identity()).ne(&tmd.signature_issuer()) {
        return Err(CertificateError::NonMatchingCertificates)
    }
    let mut hasher = Sha1::new();
    hasher.update(&tmd.to_bytes().map_err(CertificateError::IO)?[320..]);
    let tmd_hash = hasher.finalize().as_slice().to_owned();
    let public_key_modulus = BigUint::from_bytes_be(&tmd_cert.pub_key_modulus());
    let public_key_exponent = BigUint::from(tmd_cert.pub_key_exponent());
    let root_key = RsaPublicKey::new(public_key_modulus, public_key_exponent).unwrap();
    match root_key.verify(Pkcs1v15Sign::new::<Sha1>(), &tmd_hash, tmd.signature().as_slice()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verifies the signature of a Ticket using a Ticket signing certificate. The Ticket certificate
/// must match the certificate used to sign the Ticket, or this function will return an error 
/// without attempting signature verification.
pub fn verify_ticket(ticket_cert: &Certificate, ticket: &ticket::Ticket) -> Result<bool, CertificateError> {
    if !ticket_cert.signature_issuer().contains("Root-CA") || !ticket_cert.child_cert_identity().contains("XS") {
        return Err(CertificateError::IncorrectCertificate("Ticket".to_owned()));
    }
    if format!("{}-{}", ticket_cert.signature_issuer(), ticket_cert.child_cert_identity()).ne(&ticket.signature_issuer()) {
        return Err(CertificateError::NonMatchingCertificates)
    }
    let mut hasher = Sha1::new();
    hasher.update(&ticket.to_bytes().map_err(CertificateError::IO)?[320..]);
    let ticket_hash = hasher.finalize().as_slice().to_owned();
    let public_key_modulus = BigUint::from_bytes_be(&ticket_cert.pub_key_modulus());
    let public_key_exponent = BigUint::from(ticket_cert.pub_key_exponent());
    let root_key = RsaPublicKey::new(public_key_modulus, public_key_exponent).unwrap();
    match root_key.verify(Pkcs1v15Sign::new::<Sha1>(), &ticket_hash, ticket.signature().as_slice()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
