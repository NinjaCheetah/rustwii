// title/crypto.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the common crypto functions required to handle Wii content encryption.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::cipher::block_padding::ZeroPadding;
use crate::title::commonkeys::get_common_key;

// Convert a Title ID into the format required for use as the Title Key decryption IV.
fn title_id_to_iv(title_id: [u8; 8]) -> [u8; 16] {
    let mut iv: Vec<u8> = Vec::from(title_id);
    iv.resize(16, 0);
    iv.as_slice().try_into().unwrap()
}

/// Decrypts a Title Key using the specified common key and the corresponding Title ID.
pub fn decrypt_title_key(title_key_enc: [u8; 16], common_key_index: u8, title_id: [u8; 8], is_dev: bool) -> [u8; 16] {
    let iv = title_id_to_iv(title_id);
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    let decryptor = Aes128CbcDec::new(&get_common_key(common_key_index, is_dev).into(), &iv.into());
    let mut title_key = title_key_enc;
    decryptor.decrypt_padded_mut::<ZeroPadding>(&mut title_key).unwrap();
    title_key
}

/// Encrypts a Title Key using the specified common key and the corresponding Title ID.
pub fn encrypt_title_key(title_key_dec: [u8; 16], common_key_index: u8, title_id: [u8; 8], is_dev: bool) -> [u8; 16] {
    let iv = title_id_to_iv(title_id);
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let encryptor = Aes128CbcEnc::new(&get_common_key(common_key_index, is_dev).into(), &iv.into());
    let mut title_key = title_key_dec;
    encryptor.encrypt_padded_mut::<ZeroPadding>(&mut title_key, 16).unwrap();
    title_key
}

/// Decrypt content using the corresponding Title Key and content index.
pub fn decrypt_content(data: &[u8], title_key: [u8; 16], index: u16) -> Vec<u8> {
    let mut iv = Vec::from(index.to_be_bytes());
    iv.resize(16, 0);
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    let decryptor = Aes128CbcDec::new(&title_key.into(), iv.as_slice().into());
    let mut buf = data.to_owned();
    decryptor.decrypt_padded_mut::<ZeroPadding>(&mut buf).unwrap();
    buf
}

/// Encrypt content using the corresponding Title Key and content index.
pub fn encrypt_content(data: &[u8], title_key: [u8; 16], index: u16, size: u64) -> Vec<u8> {
    let mut iv = Vec::from(index.to_be_bytes());
    iv.resize(16, 0);
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let encryptor = Aes128CbcEnc::new(&title_key.into(), iv.as_slice().into());
    let mut buf = data.to_owned();
    let size = (size + 15) & !15;
    buf.resize(size as usize, 0);
    encryptor.encrypt_padded_mut::<ZeroPadding>(&mut buf, size as usize).unwrap();
    buf.resize(size as usize, 0);
    buf
}
