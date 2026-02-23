// filetypes.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Common code for identifying Wii file types.

use std::{str, fs::File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use regex::RegexBuilder;

#[derive(Debug)]
#[derive(PartialEq)]
pub enum WiiFileType {
    Wad,
    Tmd,
    Ticket,
    U8,
}

pub fn identify_file_type(input: &str) -> Option<WiiFileType> {
    let input = Path::new(input);
    let re = RegexBuilder::new(r"tmd\.?[0-9]*").case_insensitive(true).build().unwrap();
    // == TMD ==
    if re.is_match(input.to_str()?) || 
        input.file_name().is_some_and(|f| f.eq_ignore_ascii_case("tmd.bin")) ||
        input.extension().is_some_and(|f| f.eq_ignore_ascii_case("tmd")) {
        return Some(WiiFileType::Tmd);
    }
    // == Ticket ==
    if input.extension().is_some_and(|f| f.eq_ignore_ascii_case("tik")) || 
        input.file_name().is_some_and(|f| f.eq_ignore_ascii_case("ticket.bin")) ||
        input.file_name().is_some_and(|f| f.eq_ignore_ascii_case("cetk")) {
        return Some(WiiFileType::Ticket);
    }
    // == WAD ==
    if input.extension().is_some_and(|f| f.eq_ignore_ascii_case("wad")) {
        return Some(WiiFileType::Wad);
    }
    // == U8 ==
    if input.extension().is_some_and(|f| f.eq_ignore_ascii_case("arc")) ||
        input.extension().is_some_and(|f| f.eq_ignore_ascii_case("app")) {
        return Some(WiiFileType::U8);
    }
    
    // == Advanced ==
    // These require reading the magic number of the file, so we only try this after everything
    // else has been tried. These are separated from the other methods of detecting these types so
    // that we only have to open the file for reading once.
    if input.exists() {
        let mut f = File::open(input).unwrap();
        // We need to read more bytes for WADs since they don't have a proper magic number.
        let mut magic_number = vec![0u8; 8];
        f.read_exact(&mut magic_number).unwrap();
        if magic_number == b"\x00\x00\x00\x20\x49\x73\x00\x00" || magic_number == b"\x00\x00\x00\x20\x69\x62\x00\x00" {
            return Some(WiiFileType::Wad);
        }
        let mut magic_number = vec![0u8; 4];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut magic_number).unwrap();
        if magic_number == b"\x55\xAA\x38\x2D" {
            return Some(WiiFileType::U8);
        }
    }
    
    // == No match found! ==
    None
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_tmd() {
        assert_eq!(identify_file_type("tmd"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("TMD"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("tmd.bin"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("TMD.BIN"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("tmd.513"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("0000000100000002.tmd"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("0000000100000002.TMD"), Some(WiiFileType::Tmd));
    }

    #[test]
    fn test_parse_tik() {
        assert_eq!(identify_file_type("ticket.bin"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("TICKET.BIN"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("cetk"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("CETK"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("0000000100000002.tik"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("0000000100000002.TIK"), Some(WiiFileType::Ticket));
    }
    
    #[test]
    fn test_parse_wad() {
        assert_eq!(identify_file_type("0000000100000002.wad"), Some(WiiFileType::Wad));
        assert_eq!(identify_file_type("0000000100000002.WAD"), Some(WiiFileType::Wad));
    }
    
    #[test]
    fn test_parse_no_match() {
        assert_eq!(identify_file_type("somefile.txt"), None);
    }
}
