// nand/emunand.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for handling Wii EmuNANDs.

use std::fs;
use std::collections::HashMap;
use std::path::PathBuf;
use glob::glob;
use thiserror::Error;
use crate::nand::sys;
use crate::title;
use crate::title::{cert, content, ticket, tmd};

#[derive(Debug, Error)]
pub enum EmuNANDError {
    #[error("the specified title is not installed to the EmuNAND")]
    TitleNotInstalled,
    #[error("EmuNAND requires the directory `{0}`, but a file with that name already exists")]
    DirectoryNameConflict(String),
    #[error("specified EmuNAND root does not exist")]
    RootNotFound,
    #[error("uid.sys processing error")]
    UidSys(#[from] sys::UidSysError),
    #[error("certificate processing error")]
    CertificateError(#[from] cert::CertificateError),
    #[error("TMD processing error")]
    TMD(#[from] tmd::TMDError),
    #[error("Ticket processing error")]
    Ticket(#[from] ticket::TicketError),
    #[error("content processing error")]
    Content(#[from] content::ContentError),
    #[error("io error occurred during EmuNAND operation")]
    IO(#[from] std::io::Error),
}

#[derive(Debug)]
/// A structure that represents titles installed to an EmuNAND. The title_type is the Title ID high,
/// which is the type of the titles the structure represents, and titles contains a Vec of Title ID
/// lows that represent each title installed in the given type.
pub struct InstalledTitles {
    pub title_type: String,
    pub titles: Vec<String>,
}

fn safe_create_dir(dir: &PathBuf) -> Result<(), EmuNANDError> {
    if !dir.exists() {
        fs::create_dir(dir)?;
    } else if !dir.is_dir() {
        return Err(EmuNANDError::DirectoryNameConflict(dir.to_str().unwrap().to_string()));
    }
    Ok(())
}

/// An EmuNAND object that allows for creating and modifying Wii EmuNANDs.
pub struct EmuNAND {
    emunand_dirs: HashMap<String, PathBuf>,
}

impl EmuNAND {
    /// Open an existing EmuNAND in an EmuNAND instance that can be used to interact with it. This
    /// will initialize the basic directory structure if it doesn't already exist, but will not do
    /// anything beyond that.
    pub fn open(emunand_root: PathBuf) -> Result<Self, EmuNANDError> {
        if !emunand_root.exists() {
            return Err(EmuNANDError::RootNotFound);
        }
        let mut emunand_dirs: HashMap<String, PathBuf> = HashMap::new();
        emunand_dirs.insert(String::from("root"), emunand_root.clone());
        emunand_dirs.insert(String::from("import"), emunand_root.join("import"));
        emunand_dirs.insert(String::from("meta"), emunand_root.join("meta"));
        emunand_dirs.insert(String::from("shared1"), emunand_root.join("shared1"));
        emunand_dirs.insert(String::from("shared2"), emunand_root.join("shared2"));
        emunand_dirs.insert(String::from("sys"), emunand_root.join("sys"));
        emunand_dirs.insert(String::from("ticket"), emunand_root.join("ticket"));
        emunand_dirs.insert(String::from("title"), emunand_root.join("title"));
        emunand_dirs.insert(String::from("tmp"), emunand_root.join("tmp"));
        emunand_dirs.insert(String::from("wfs"), emunand_root.join("wfs"));
        for dir in emunand_dirs.keys() {
            if !emunand_dirs[dir].exists() {
                fs::create_dir(&emunand_dirs[dir])?;
            } else if !emunand_dirs[dir].is_dir() {
                return Err(EmuNANDError::DirectoryNameConflict(emunand_dirs[dir].to_str().unwrap().to_string()));
            }
        }
        Ok(EmuNAND {
            emunand_dirs,
        })
    }
    
    /// Gets the path to a directory in the root of an EmuNAND, if it's a valid directory.
    pub fn get_emunand_dir(&self, dir: &str) -> Option<&PathBuf> {
        self.emunand_dirs.get(dir)
    }
    
    /// Scans titles installed to an EmuNAND and returns a Vec of InstalledTitles instances.
    pub fn get_installed_titles(&self) -> Vec<InstalledTitles> {
        // Scan TID highs in /title/ first.
        let tid_highs: Vec<PathBuf> = glob(&format!("{}/*", self.emunand_dirs["title"].display()))
            .unwrap().filter_map(|f| f.ok()).collect();
        // Iterate over the TID lows in each TID high, and save every title where
        // /title/<tid_high>/<tid_low>/title.tmd exists.
        let mut installed_titles: Vec<InstalledTitles> = Vec::new();
        for high in tid_highs {
            if high.is_dir() {
                let tid_lows: Vec<PathBuf> = glob(&format!("{}/*", high.display()))
                    .unwrap().filter_map(|f| f.ok()).collect();
                let mut valid_lows: Vec<String> = Vec::new();
                for low in tid_lows {
                    if low.join("content").join("title.tmd").exists() {
                        valid_lows.push(low.file_name().unwrap().to_str().unwrap().to_string().to_ascii_uppercase());
                    }
                }
                installed_titles.push(InstalledTitles {
                    title_type: high.file_name().unwrap().to_str().unwrap().to_string().to_ascii_uppercase(),
                    titles: valid_lows,
                })
            }
        }
        installed_titles
    }
    
    /// Get the Ticket for a title installed to an EmuNAND. Returns a Ticket instance if a Ticket
    /// with the specified Title ID can be found, or None if not.
    pub fn get_title_ticket(&self, tid: [u8; 8]) -> Option<ticket::Ticket> {
        let ticket_path = self.emunand_dirs["title"]
            .join(hex::encode(&tid[0..4]))
            .join(format!("{}.tik", hex::encode(&tid[4..8])));
        if ticket_path.exists() {
            match fs::read(&ticket_path) {
                Ok(content) => {
                    ticket::Ticket::from_bytes(&content).ok()
                },
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /// Get the TMD for a title installed to an EmuNAND. Returns a Ticket instance if a TMD with the
    /// specified Title ID can be found, or None if not.
    pub fn get_title_tmd(&self, tid: [u8; 8]) -> Option<tmd::TMD> {
        let tmd_path = self.emunand_dirs["title"]
            .join(hex::encode(&tid[0..4]))
            .join(hex::encode(&tid[4..8]).to_ascii_lowercase())
            .join("content")
            .join("title.tmd");
        if tmd_path.exists() {
            match fs::read(&tmd_path) {
                Ok(content) => {
                    tmd::TMD::from_bytes(&content).ok()
                },
                Err(_) => None,
            }
        } else {
            None
        }
    }
    
    /// Install the provided title to an EmuNAND, mimicking a WAD installation performed by ES. The 
    /// "override meta" option will install the content at index 0 as title.met, instead of any 
    /// actual meta/footer data contained in the title.
    pub fn install_title(&self, title: title::Title, override_meta: bool) -> Result<(), EmuNANDError> {
        // Save the two halves of the TID, since those are part of the installation path.
        let tid_high = hex::encode(&title.tmd.title_id()[0..4]);
        let tid_low = hex::encode(&title.tmd.title_id()[4..8]);
        // Tickets are installed to /ticket/<tid_high>/<tid_low>.tik.
        let ticket_dir = self.emunand_dirs["ticket"].join(&tid_high);
        safe_create_dir(&ticket_dir)?;
        fs::write(ticket_dir.join(format!("{}.tik", &tid_low)), title.ticket.to_bytes()?)?;
        // TMDs and normal content (non-shared) are installed to 
        // /title/<tid_high>/<tid_low>/content/, as title.tmd and <cid>.app.
        let mut title_dir = self.emunand_dirs["title"].join(&tid_high);
        safe_create_dir(&title_dir)?;
        title_dir = title_dir.join(&tid_low);
        safe_create_dir(&title_dir)?;
        // Create an empty "data" dir if it doesn't exist.
        safe_create_dir(&title_dir.join("data"))?;
        title_dir = title_dir.join("content");
        // Delete any existing installed content/the current TMD.
        if title_dir.exists() {
            fs::remove_dir_all(&title_dir)?;
        }
        fs::create_dir(&title_dir)?;
        fs::write(title_dir.join("title.tmd"), title.tmd.to_bytes()?)?;
        for i in 0..title.content.content_records().len() {
            if matches!(title.content.content_records()[i].content_type, tmd::ContentType::Normal) {
                let content_path = title_dir.join(format!("{:08X}.app", title.content.content_records()[i].content_id).to_ascii_lowercase());
                fs::write(content_path, title.get_content_by_index(i)?)?;
            }
        }
        // Shared content needs to be installed to /shared1/, with incremental names decided by
        // the records in /shared1/content.map.
        // Start by checking for a map and loading it if it exists, so that we know what shared
        // content is already installed.
        let content_map_path = self.emunand_dirs["shared1"].join("content.map");
        let mut content_map = if content_map_path.exists() {
            content::SharedContentMap::from_bytes(&fs::read(&content_map_path)?)?
        } else {
            content::SharedContentMap::new()
        };
        for i in 0..title.content.content_records().len() {
            if matches!(title.content.content_records()[i].content_type, tmd::ContentType::Shared) {
                if let Some(file_name) = content_map.add(&title.content.content_records()[i].content_hash)? {
                    let content_path = self.emunand_dirs["shared1"].join(format!("{}.app", file_name.to_ascii_lowercase()));
                    fs::write(content_path, title.get_content_by_index(i)?)?;
                }
            }
        }
        fs::write(&content_map_path, content_map.to_bytes()?)?;
        // The "footer" (officially "meta") is installed to /meta/<tid_high>/<tid_low>/title.met.
        // The "override meta" option installs the content at index 0 to title.met instead, as that
        // content contains the banner, and that's what title.met is meant to hold.
        let meta_data = if override_meta {
            title.get_content_by_index(0)?
        } else {
            title.meta()
        };
        if !meta_data.is_empty() {
            let mut meta_dir = self.emunand_dirs["meta"].join(&tid_high);
            safe_create_dir(&meta_dir)?;
            meta_dir = meta_dir.join(&tid_low);
            safe_create_dir(&meta_dir)?;
            fs::write(meta_dir.join("title.met"), meta_data)?;
        }
        // Finally, we need to update uid.sys (or create it if it doesn't exist) so that the newly
        // installed title will actually show up (at least for channels).
        let uid_sys_path = self.emunand_dirs["sys"].join("uid.sys");
        let mut uid_sys = if uid_sys_path.exists() {
            sys::UidSys::from_bytes(&fs::read(&uid_sys_path)?)?
        } else {
            sys::UidSys::new()
        };
        uid_sys.add(&title.tmd.title_id())?;
        fs::write(&uid_sys_path, &uid_sys.to_bytes()?)?;
        Ok(())
    }
    
    /// Uninstall a title with the provided Title ID from an EmuNAND. By default, the Ticket will be
    /// left intact unlesss "remove ticket" is set to true.
    pub fn uninstall_title(&self, tid: [u8; 8], remove_ticket: bool) -> Result<(), EmuNANDError> {
        // Save the two halves of the TID, since those are part of the installation path.
        let tid_high = hex::encode(&tid[0..4]);
        let tid_low = hex::encode(&tid[4..8]);
        // Ensure that a title directory actually exists for the specified title. If it does, then
        // delete it.
        let title_dir = self.emunand_dirs["title"].join(&tid_high).join(&tid_low);
        if !title_dir.exists() {
            return Err(EmuNANDError::TitleNotInstalled);
        }
        fs::remove_dir_all(&title_dir)?;
        // If we've been told to delete the Ticket, check if it exists and then do so.
        if remove_ticket {
            let ticket_path = self.emunand_dirs["ticket"].join(&tid_high).join(format!("{}.tik", &tid_low));
            if ticket_path.exists() {
                fs::remove_file(&ticket_path)?;
            }
        }
        Ok(())
    }
}
