// title/versions.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Handles converting Title version formats, and provides Wii Menu version constants.

use std::collections::HashMap;

fn wii_menu_versions_map(vwii: Option<bool>) -> HashMap<u16, String> {
    let mut menu_versions: HashMap<u16, String> = HashMap::new();
    if vwii == Some(true) {
        menu_versions.insert(512, "vWii-1.0.0J".to_string());
        menu_versions.insert(513, "vWii-1.0.0U".to_string());
        menu_versions.insert(514, "vWii-1.0.0E".to_string());
        menu_versions.insert(544, "vWii-4.0.0J".to_string());
        menu_versions.insert(545, "vWii-4.0.0U".to_string());
        menu_versions.insert(546, "vWii-4.0.0E".to_string());
        menu_versions.insert(608, "vWii-5.2.0J".to_string());
        menu_versions.insert(609, "vWii-5.2.0U".to_string());
        menu_versions.insert(610, "vWii-5.2.0E".to_string());
    } else {
        menu_versions.insert( 0, "Prelaunch".to_string());
        menu_versions.insert( 1, "Prelaunch".to_string());
        menu_versions.insert( 2, "Prelaunch".to_string());
        menu_versions.insert( 64, "1.0J".to_string());
        menu_versions.insert( 33, "1.0U".to_string());
        menu_versions.insert( 34, "1.0E".to_string());
        menu_versions.insert( 128, "2.0J".to_string());
        menu_versions.insert( 97, "2.0U".to_string());
        menu_versions.insert( 130, "2.0E".to_string());
        menu_versions.insert( 162, "2.1E".to_string());
        menu_versions.insert( 192, "2.2J".to_string());
        menu_versions.insert( 193, "2.2U".to_string());
        menu_versions.insert( 194, "2.2E".to_string());
        menu_versions.insert( 224, "3.0J".to_string());
        menu_versions.insert( 225, "3.0U".to_string());
        menu_versions.insert( 226, "3.0E".to_string());
        menu_versions.insert( 256, "3.1J".to_string());
        menu_versions.insert( 257, "3.1U".to_string());
        menu_versions.insert( 258, "3.1E".to_string());
        menu_versions.insert( 288, "3.2J".to_string());
        menu_versions.insert( 289, "3.2U".to_string());
        menu_versions.insert( 290, "3.2E".to_string());
        menu_versions.insert( 352, "3.3J".to_string());
        menu_versions.insert( 353, "3.3U".to_string());
        menu_versions.insert( 354, "3.3E".to_string());
        menu_versions.insert( 326, "3.3K".to_string());
        menu_versions.insert( 384, "3.4J".to_string());
        menu_versions.insert( 385, "3.4U".to_string());
        menu_versions.insert( 386, "3.4E".to_string());
        menu_versions.insert( 390, "3.5K".to_string());
        menu_versions.insert( 416, "4.0J".to_string());
        menu_versions.insert( 417, "4.0U".to_string());
        menu_versions.insert( 418, "4.0E".to_string());
        menu_versions.insert( 448, "4.1J".to_string());
        menu_versions.insert( 449, "4.1U".to_string());
        menu_versions.insert( 450, "4.1E".to_string());
        menu_versions.insert( 454, "4.1K".to_string());
        menu_versions.insert( 480, "4.2J".to_string());
        menu_versions.insert( 481, "4.2U".to_string());
        menu_versions.insert( 482, "4.2E".to_string());
        menu_versions.insert( 486, "4.2K".to_string());
        menu_versions.insert( 512, "4.3J".to_string());
        menu_versions.insert( 513, "4.3U".to_string());
        menu_versions.insert( 514, "4.3E".to_string());
        menu_versions.insert( 518, "4.3K".to_string());
        menu_versions.insert( 4609, "4.3U-Mini".to_string());
        menu_versions.insert( 4610, "4.3E-Mini".to_string());
    }
    menu_versions
}

/// Converts the decimal version of a title (vXXX) into a more standard format for applicable
/// titles. For the Wii Menu, this uses the optional vwii argument and a hash table to determine
/// the user-friendly version number, as there is no way to directly derive it from the decimal
/// format.
pub fn dec_to_standard(version: u16, title_id: &str, vwii: Option<bool>) -> Option<String> {
    if title_id == "0000000100000002" {
        let map = wii_menu_versions_map(vwii);
        map.get(&version).cloned()
    } else {
        Some(format!("{}.{}", version >> 8, version & 0xF))
    }
}
