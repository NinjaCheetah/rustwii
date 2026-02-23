// title/commonkeys.rs from rustwii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii

const COMMON_KEY: &str = "ebe42a225e8593e448d9c5457381aaf7";
const KOREAN_KEY: &str = "63b82bb4f4614e2e13f2fefbba4c9b7e";
const VWII_KEY: &str = "30bfc76e7c19afbb23163330ced7c28d";
const DEV_COMMON_KEY: &str = "a1604a6a7123b529ae8bec32c816fcaa";

/// Returns the common key for the specified index. Providing Some(true) for the optional argument
/// is_dev will make index 0 return the development common key instead of the retail common key.
pub fn get_common_key(index: u8, is_dev: bool) -> [u8; 16] {
    // Match the Korean and vWii keys, and if they don't match then fall back on the common key.
    // The is_dev argument is an option, and if it's set to false or None, then the regular
    // common key will be used.
    let selected_key: &str;
    match index {
        1 => selected_key = KOREAN_KEY,
        2 => selected_key = VWII_KEY,
        _ => {
            match is_dev {
                true => selected_key = DEV_COMMON_KEY,
                false => selected_key = COMMON_KEY,
            }
        }
    }
    hex::decode(selected_key).unwrap().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_common_key() {
        assert_eq!(get_common_key(0, false), [0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7]);
    }
    #[test]
    fn test_get_invalid_index() {
        assert_eq!(get_common_key(57, false), [0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7]);
    }
    #[test]
    fn test_get_korean_key() {
        assert_eq!(get_common_key(1, false), [0x63, 0xb8, 0x2b, 0xb4, 0xf4, 0x61, 0x4e, 0x2e, 0x13, 0xf2, 0xfe, 0xfb, 0xba, 0x4c, 0x9b, 0x7e]);
    }
    #[test]
    fn test_get_vwii_key() {
        assert_eq!(get_common_key(2, false), [0x30, 0xbf, 0xc7, 0x6e, 0x7c, 0x19, 0xaf, 0xbb, 0x23, 0x16, 0x33, 0x30, 0xce, 0xd7, 0xc2, 0x8d]);
    }
    #[test]
    fn test_get_dev_key() {
        assert_eq!(get_common_key(0, true), [0xa1, 0x60, 0x4a, 0x6a, 0x71, 0x23, 0xb5, 0x29, 0xae, 0x8b, 0xec, 0x32, 0xc8, 0x16, 0xfc, 0xaa]);
    }
}
