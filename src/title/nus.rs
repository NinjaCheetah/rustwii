// title/nus.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the functions required for downloading data from the NUS.

use std::str;
use std::io::Write;
use reqwest;
use thiserror::Error;
use crate::title::{cert, tmd, ticket, content};
use crate::title;

const WII_NUS_ENDPOINT: &str = "http://nus.cdn.shop.wii.com/ccs/download/";
const WII_U_NUS_ENDPOINT: &str = "http://ccs.cdn.wup.shop.nintendo.net/ccs/download/";

#[derive(Debug, Error)]
pub enum NUSError {
    #[error("the data returned by the NUS is not valid")]
    InvalidData,
    #[error("the requested Title ID or version could not be found on the NUS")]
    NotFound,
    #[error("Certificate processing error")]
    Certificate(#[from] cert::CertificateError),
    #[error("TMD processing error")]
    TMD(#[from] tmd::TMDError),
    #[error("Ticket processing error")]
    Ticket(#[from] ticket::TicketError),
    #[error("Content processing error")]
    Content(#[from] content::ContentError),
    #[error("an error occurred while assembling a Title from the downloaded data")]
    Title(#[from] title::TitleError),
    #[error("data could not be downloaded from the NUS")]
    Request(#[from] reqwest::Error),
    #[error("an error occurred writing NUS data")]
    IO(#[from] std::io::Error),
}

/// Downloads the retail certificate chain from the NUS.
pub fn download_cert_chain(wiiu_endpoint: bool) -> Result<Vec<u8>, NUSError> {
    // To build the certificate chain, we need to download both the TMD and Ticket of a title. For
    // the sake of simplicity, we'll use the Wii Menu 4.3U because I already found the required TMD
    // and Ticket offsets for it.
    let endpoint_url = if wiiu_endpoint {
        WII_U_NUS_ENDPOINT.to_owned()
    } else {
        WII_NUS_ENDPOINT.to_owned()
    };
    let tmd_url = format!("{}0000000100000002/tmd.513", endpoint_url);
    let tik_url = format!("{}0000000100000002/cetk", endpoint_url);
    let client = reqwest::blocking::Client::new();
    let tmd = client.get(tmd_url).header(reqwest::header::USER_AGENT, "wii libnup/1.0").send()?.bytes()?;
    let tik = client.get(tik_url).header(reqwest::header::USER_AGENT, "wii libnup/1.0").send()?.bytes()?;
    // Assemble the certificate chain.
    let mut cert_chain: Vec<u8> = Vec::new();
    // Certificate Authority data.
    cert_chain.write_all(&tik[0x2A4 + 768..])?;
    // Certificate Policy (TMD certificate) data.
    cert_chain.write_all(&tmd[0x328..0x328 + 768])?;
    // XS (Ticket certificate) data.
    cert_chain.write_all(&tik[0x2A4..0x2A4 + 768])?;
    Ok(cert_chain)
}

/// Downloads a specified content file from the specified title from the NUS.
pub fn download_content(title_id: [u8; 8], content_id: u32, wiiu_endpoint: bool) -> Result<Vec<u8>, NUSError> {
    // Build the download URL. The structure is download/<TID>/<CID>
    let endpoint_url = if wiiu_endpoint {
        WII_U_NUS_ENDPOINT.to_owned()
    } else {
        WII_NUS_ENDPOINT.to_owned()
    };
    let content_url = format!("{}{}/{:08X}", endpoint_url, &hex::encode(title_id), content_id);
    let client = reqwest::blocking::Client::new();
    let response = client.get(content_url).header(reqwest::header::USER_AGENT, "wii libnup/1.0").send()?;
    if !response.status().is_success() {
        return Err(NUSError::NotFound);
    }
    Ok(response.bytes()?.to_vec())
}

/// Downloads all contents from the specified title from the NUS.
pub fn download_contents(tmd: &tmd::TMD, wiiu_endpoint: bool) -> Result<Vec<Vec<u8>>, NUSError> {
    let content_ids: Vec<u32> = tmd.content_records().iter().map(|record| { record.content_id }).collect();
    let mut contents: Vec<Vec<u8>> = Vec::new();
    for id in content_ids {
        contents.push(download_content(tmd.title_id(), id, wiiu_endpoint)?);
    }
    Ok(contents)
}

/// Downloads the Ticket for a specified Title ID from the NUS, if it's available.
pub fn download_ticket(title_id: [u8; 8], wiiu_endpoint: bool) -> Result<Vec<u8>, NUSError> {
    // Build the download URL. The structure is download/<TID>/cetk.
    let endpoint_url = if wiiu_endpoint {
        WII_U_NUS_ENDPOINT.to_owned()
    } else {
        WII_NUS_ENDPOINT.to_owned()
    };
    let tik_url = format!("{}{}/cetk", endpoint_url, &hex::encode(title_id));
    let client = reqwest::blocking::Client::new();
    let response = client.get(tik_url).header(reqwest::header::USER_AGENT, "wii libnup/1.0").send()?;
    if !response.status().is_success() {
        return Err(NUSError::NotFound);
    }
    let tik = ticket::Ticket::from_bytes(&response.bytes()?).map_err(|_| NUSError::InvalidData)?;
    tik.to_bytes().map_err(|_| NUSError::InvalidData)
}

/// Downloads an entire title with all of its content from the NUS and returns a Title instance.
pub fn download_title(title_id: [u8; 8], title_version: Option<u16>, wiiu_endpoint: bool) -> Result<title::Title, NUSError> {
    // Download the individual components of a title and then build a title from them.
    let cert_chain = cert::CertificateChain::from_bytes(&download_cert_chain(wiiu_endpoint)?)?;
    let tmd = tmd::TMD::from_bytes(&download_tmd(title_id, title_version, wiiu_endpoint)?)?;
    let tik = ticket::Ticket::from_bytes(&download_ticket(title_id, wiiu_endpoint)?)?;
    let content_region = content::ContentRegion::from_contents(download_contents(&tmd, wiiu_endpoint)?, tmd.content_records().clone())?;
    let title = title::Title::from_parts(cert_chain, None, tik, tmd, content_region, None)?;
    Ok(title)
}

/// Downloads the TMD for a specified Title ID from the NUS.
pub fn download_tmd(title_id: [u8; 8], title_version: Option<u16>, wiiu_endpoint: bool) -> Result<Vec<u8>, NUSError> {
    // Build the download URL. The structure is download/<TID>/tmd for latest and 
    // download/<TID>/tmd.<version> for when a specific version is requested.
    let endpoint_url = if wiiu_endpoint {
        WII_U_NUS_ENDPOINT.to_owned()
    } else {
        WII_NUS_ENDPOINT.to_owned()
    };
    let tmd_url = if title_version.is_some() {
        format!("{}{}/tmd.{}", endpoint_url, &hex::encode(title_id), title_version.unwrap())
    } else {
        format!("{}{}/tmd", endpoint_url, &hex::encode(title_id))
    };
    let client = reqwest::blocking::Client::new();
    let response = client.get(tmd_url).header(reqwest::header::USER_AGENT, "wii libnup/1.0").send()?;
    if !response.status().is_success() {
        return Err(NUSError::NotFound);
    }
    let tmd = tmd::TMD::from_bytes(&response.bytes()?).map_err(|_| NUSError::InvalidData)?;
    tmd.to_bytes().map_err(|_| NUSError::InvalidData)
}
