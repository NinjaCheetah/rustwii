// media/banner.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for parsing channel banners.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use md5;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use strum_macros::EnumIter;
use thiserror::Error;
use crate::archive::u8;

#[derive(Debug, Error)]
pub enum IMETHeaderError {
    #[error("this does not appear to be an IMET header (missing magic number)")]
    NotIMETHeader,
    #[error("specified channel name exceeds the 42 character limit")]
    ChannelNameTooLong,
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
}

#[derive(Debug, Clone, Copy, EnumIter)]
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
        for _ in 0..10 {
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
            channel_names
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, IMETHeaderError> {
        // The header starts with 0x40 bytes of padding. This is important, because that
        // padding is part of the data used to calculate the hash.
        let mut buf: Vec<u8> = vec![0; 0x40];
        buf.write_all(&self.magic)?;
        buf.write_u32::<BigEndian>(self.header_size)?;
        buf.write_u32::<BigEndian>(self.version)?;
        for size in self.sizes {
            buf.write_u32::<BigEndian>(size)?;
        }
        buf.write_u32::<BigEndian>(self.flag1)?;
        for name in &self.channel_names {
            // Fixed length of 84 bytes since every string is maximum 42 characters.
            write_utf16be_fixed(&mut buf, name, 84)?;
        }
        buf.resize(buf.len() + 588, 0);
        // Add a blank hash, then get the MD5 hash of the entire thing.
        buf.resize(buf.len() + 16, 0);
        let md5_hash = md5::compute(&buf);
        buf.truncate(buf.len() - 16);
        buf.write_all(md5_hash.as_slice())?;

        Ok(buf)
    }

    pub fn new(sizes: [u32; 3]) -> Result<Self, IMETHeaderError> {
        Ok(Self {
            magic: b"IMET".to_owned(),
            header_size: 1536, // the header size is fixed so this is safe
            version: 3, // this value is always 3 apparently so use that as the default
            flag1: 0, // nobody seems to even know what this does
            channel_names: vec![],
            sizes
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn channel_name(&self, language: TitleLanguage) -> String {
        self.channel_names[language as usize].clone()
    }

    pub fn set_channel_name(&mut self, language: TitleLanguage, name: String) -> Result<(), IMETHeaderError> {
        if name.len() > 42 {
            return Err(IMETHeaderError::ChannelNameTooLong)
        }
        self.channel_names[language as usize] = name;
        Ok(())
    }
}

fn write_utf16be_fixed<W: Write>(mut w: W, s: &str, byte_len: usize) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(byte_len);

    for code_unit in s.encode_utf16() {
        out.extend_from_slice(&code_unit.to_be_bytes());
    }

    out.resize(byte_len, 0);
    out.truncate(byte_len);

    w.write_all(&out)
}

#[derive(Debug, Error)]
pub enum BannerError {
    #[error("U8 archive error")]
    U8Error(#[from] u8::U8Error),
    #[error("IMET header error")]
    IMETHeaderError(#[from] IMETHeaderError),
    #[error("this U8 archive is not a banner (missing IMET header)")]
    NotBanner,
    #[error("IO error fill this in later kthx")]
    IO(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Banner {
    u8_root: u8::U8Directory,
    imet_header: IMETHeader
}

impl Banner {
    pub fn from_bytes(data: &[u8]) -> Result<Self, BannerError> {
        let mut buf = Cursor::new(data);
        let mut magic = [0u8; 4];
        let u8_archive_start: usize;
        let imet_header: IMETHeader;
        // Check for an IMET header immediately at the start of the file.
        buf.seek(SeekFrom::Start(0x40))?;
        buf.read_exact(&mut magic)?;
        if &magic == b"\x49\x4D\x45\x54" {
            // IMET with no build tag means the U8 archive should start at 0x600.
            u8_archive_start = 0x600;
            imet_header = IMETHeader::from_bytes(&buf.get_mut()[..1536])?;
        }
        // Check for an IMET header that comes after a build tag.
        else {
            buf.seek(SeekFrom::Start(0x80))?;
            buf.read_exact(&mut magic)?;
            if &magic == b"\x49\x4D\x45\x54" {
                // IMET with a build tag means the U8 archive should start at 0x600.
                u8_archive_start = 0x640;
                imet_header = IMETHeader::from_bytes(&buf.get_mut()[0x40..0x40 + 1536])?;
            }
            // We didn't find the header, so this isn't a banner (or it is, but it's malformed).
            else {
                return Err(BannerError::NotBanner)
            }
        }
        let u8_root = u8::U8Directory::from_bytes(buf.get_mut()[u8_archive_start..].to_vec().into_boxed_slice())?;

        Ok(Self {
            u8_root,
            imet_header
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BannerError> {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_all(&self.imet_header.to_bytes()?)?;
        buf.write_all(&self.u8_root.to_bytes()?)?;
        Ok(buf)
    }

    pub fn u8_root(&self) -> &u8::U8Directory {
        &self.u8_root
    }

    pub fn imet_header(&self) -> &IMETHeader {
        &self.imet_header
    }

    pub fn set_u8_root(&mut self, u8_root: u8::U8Directory) {
        self.u8_root = u8_root
    }

    pub fn set_imet_header(&mut self, imet_header: IMETHeader) {
        self.imet_header = imet_header
    }
}
