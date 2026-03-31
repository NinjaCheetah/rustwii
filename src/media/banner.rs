// media/banner.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for parsing channel banners.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IMETHeaderError {
    #[error("this does not appear to be an IMET header (missing magic number)")]
    NotIMETHeader,
    #[error("IO error fill this in later kthx")]
    IO(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct IMETHeader {
    magic: [u8; 4],
    header_size: u32,
    version: u32,
    sizes: [u32; 3],
    flag1: u32,
    channel_names: Vec<String>,
    md5_hash: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
pub enum TitleLanguage {
    Japanese = 0,
    English = 1,
    German = 2,
    French = 3,
    Spanish = 4,
    Italian = 5,
    Dutch = 6,
    ChineseSimplified = 7,
    ChineseTraditional = 8,
    Korean = 9
}

impl IMETHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, IMETHeaderError> {
        let mut buf = Cursor::new(data);
        buf.seek(SeekFrom::Start(0x40))?;
        let mut magic = [0u8; 4];
        buf.read_exact(&mut magic)?;
        if &magic != b"IMET" {
            return Err(IMETHeaderError::NotIMETHeader);
        }

        let header_size = buf.read_u32::<BigEndian>()?;
        let version = buf.read_u32::<BigEndian>()?;
        let mut sizes = [0u32; 3];
        for i in 0..3 {
            sizes[i] = buf.read_u32::<BigEndian>()?;
        }
        let flag1 = buf.read_u32::<BigEndian>()?;
        let mut channel_names: Vec<String> = vec![];
        for i in 0..10 {
            let mut name_raw = [0u8; 84];
            buf.read_exact(&mut name_raw)?;
            let name_u16: Vec<u16> = name_raw
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            channel_names.push(String::from_utf16_lossy(&name_u16).replace("\x00", ""));
        }
        buf.seek(SeekFrom::Start(buf.position() + 588))?;
        let mut md5_hash = [0u8; 16];
        buf.read_exact(&mut md5_hash)?;

        Ok(Self {
            magic,
            header_size,
            version,
            sizes,
            flag1,
            channel_names,
            md5_hash
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IMETHeaderError> {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_all(&self.magic)?;
        buf.write_u32::<BigEndian>(self.header_size)?;
        buf.write_u32::<BigEndian>(self.version)?;
        for size in self.sizes {
            buf.write_u32::<BigEndian>(size)?;
        }
        buf.write_u32::<BigEndian>(self.flag1)?;
        for name in self.channel_names {
            let name_encoded = name.encode_utf16()
        }


        Ok(buf)
    }

    pub fn get_channel_name(&self, language: TitleLanguage) -> String {
        self.channel_names[language as usize].clone()
    }
}
