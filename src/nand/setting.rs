// nand/setting.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for parsing and editing setting.txt in the Wii
// Menu's data.

use std::collections::HashMap;
use std::io::Cursor;
use byteorder::ReadBytesExt;

const SETTINGS_KEY: u32 = 0x73B5DBFA;

/// A structure that allows for encrypting, decrypting, parsing, and editing a setting.txt file.
pub struct SettingTxt {
    pub area: String,
    pub model: String,
    pub dvd: u8,
    pub mpch: String,
    pub code: String,
    pub serial_number: String,
    pub video: String,
    pub game: String,
}

impl SettingTxt {
    /// Creates a new SettingTxt instance from the binary data of an encrypted setting.txt file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, std::io::Error> {
        // Unlike most files we have to deal with, setting.txt is encrypted. This means we need to
        // decrypt it first, and *then* we can parse it.
        let mut buf = Cursor::new(data);
        let mut key: u32 = SETTINGS_KEY;
        let mut dec_data: Vec<u8> = Vec::new();
        for _ in 0..256 {
            dec_data.push(buf.read_u8()? ^ (key & 0xFF) as u8);
            key = key.rotate_left(1); // Automatic bit rotation!? Thanks for the tip clippy!
        }
        let setting_str = String::from_utf8_lossy(&dec_data);
        let setting_str = setting_str[0..setting_str.clone().rfind('\n').unwrap_or(setting_str.len() - 2) + 1].to_string();
        let setting_txt = SettingTxt::from_string(setting_str)?;
        Ok(setting_txt)
    }

    /// Creates a new SettingTxt instance from the decrypted text of a setting.txt file.
    pub fn from_string(data: String) -> Result<Self, std::io::Error> {
        let mut setting_keys: HashMap<String, String> = HashMap::new();
        for line in data.lines() {
            let (key, value) = line.split_once("=").unwrap();
            setting_keys.insert(key.to_owned(), value.to_owned());
        }
        let area = setting_keys["AREA"].to_string();
        let model = setting_keys["MODEL"].to_string();
        let dvd = setting_keys["DVD"].as_str().parse::<u8>().unwrap();
        let mpch = setting_keys["MPCH"].to_string();
        let code = setting_keys["CODE"].to_string();
        let serial_number = setting_keys["SERNO"].to_string();
        let video = setting_keys["VIDEO"].to_string();
        let game = setting_keys["GAME"].to_string();
        Ok(SettingTxt {
            area,
            model,
            dvd,
            mpch,
            code,
            serial_number,
            video,
            game,
        })
    }
    
    /// Encrypts and then dumps the data in a SettingTxt instance back into binary data that can be
    /// written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let setting_str = self.to_string()?;
        let setting_bytes = setting_str.as_bytes();
        let mut buf = Cursor::new(setting_bytes);
        let mut key: u32 = SETTINGS_KEY;
        let mut enc_data: Vec<u8> = Vec::new();
        for _ in 0..setting_str.len() {
            enc_data.push(buf.read_u8()? ^ (key & 0xFF) as u8);
            key = key.rotate_left(1);
        }
        enc_data.resize(256, 0);
        Ok(enc_data)
    }
    
    /// Dumps the decrypted data in a SettingTxt instance into a string that can be written to a
    /// file.
    pub fn to_string(&self) -> Result<String, std::io::Error> {
        let mut setting_str = String::new();
        setting_str += &format!("AREA={}\r\n", self.area);
        setting_str += &format!("MODEL={}\r\n", self.model);
        setting_str += &format!("DVD={}\r\n", self.dvd);
        setting_str += &format!("MPCH={}\r\n", self.mpch);
        setting_str += &format!("CODE={}\r\n", self.code);
        setting_str += &format!("SERNO={}\r\n", self.serial_number);
        setting_str += &format!("VIDEO={}\r\n", self.video);
        setting_str += &format!("GAME={}\r\n", self.game);
        Ok(setting_str)
    }
}
