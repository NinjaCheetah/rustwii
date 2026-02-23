// archive/u8.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for parsing U8 archives.

use std::cell::RefCell;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::rc::{Rc, Weak};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum U8Error {
    #[error("the requested item could not be found in this U8 archive")]
    ItemNotFound(String),
    #[error("found invalid node type {0} while processing node at index {1}")]
    InvalidNodeType(u8, usize),
    #[error("invalid file name at offset {0}")]
    InvalidFileName(u64),
    #[error("this does not appear to be a U8 archive (missing magic number)")]
    NotU8Data,
    #[error("U8 data is not in a valid format")]
    IO(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct U8Directory {
    pub name: String,
    pub parent: Option<Weak<RefCell<U8Directory>>>,
    pub dirs: Vec<Rc<RefCell<U8Directory>>>,
    pub files: Vec<Rc<RefCell<U8File>>>,
}

#[derive(Clone, Debug)]
pub struct U8File {
    pub name: String,
    pub data: Vec<u8>,
    pub parent: Option<Weak<RefCell<U8Directory>>>,
}

impl U8Directory {
    pub fn new(name: String) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            name,
            parent: None,
            dirs: Vec::new(),
            files: Vec::new(),
        }))
    }

    pub fn add_dir(parent: &Rc<RefCell<Self>>, child: Rc<RefCell<Self>>) {
        child.borrow_mut().parent = Some(Rc::downgrade(parent));
        parent.borrow_mut().dirs.push(child);
    }

    pub fn add_file(parent: &Rc<RefCell<Self>>, file: Rc<RefCell<U8File>>) {
        file.borrow_mut().parent = Some(Rc::downgrade(parent));
        parent.borrow_mut().files.push(file);
    }

    pub fn get_parent(&self) -> Option<Rc<RefCell<U8Directory>>> {
        self.parent.as_ref()?.upgrade()
    }

    pub fn get_child_dir(parent: &Rc<RefCell<U8Directory>>, name: &str) -> Option<Rc<RefCell<U8Directory>>> {
        parent.borrow().dirs.iter()
            .find(|dir| dir.borrow().name == name)
            .map(Rc::clone)
    }
    
    fn count_recursive(dir: &Rc<RefCell<U8Directory>>, count: &mut usize) {
        *count += dir.borrow().files.len();
        for dir in dir.borrow().dirs.iter() {
            *count += 1;
            Self::count_recursive(dir, count);
        }
    }
    
    pub fn count(&self) -> usize {
        let mut count: usize = 1;
        count += self.files.len();
        for dir in &self.dirs {
            count += 1;
            Self::count_recursive(dir, &mut count);
        }
        count
    }
}

impl U8File {
    pub fn new(name: String, data: Vec<u8>) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            name,
            data,
            parent: None,
        }))
    }

    pub fn get_parent(&self) -> Option<Rc<RefCell<U8Directory>>> {
        self.parent.as_ref()?.upgrade()
    }
}

#[derive(Clone, Debug)]
pub struct U8Node {
    pub node_type: u8,
    pub name_offset: u32, // This is really type u24, so the most significant byte will be ignored.
    pub data_offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug)]
pub struct U8Archive {
    pub node_tree: Rc<RefCell<U8Directory>>,
}

impl U8Archive {
    /// Creates a new U8 instance from the binary data of a U8 file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, U8Error> {
        let mut buf = Cursor::new(data);
        let mut magic = [0u8; 4];
        buf.read_exact(&mut magic)?;
        // Check for an IMET header if the magic number isn't the correct value before throwing an
        // error.
        if &magic != b"\x55\xAA\x38\x2D" {
            // Check for an IMET header immediately at the start of the file.
            buf.seek(SeekFrom::Start(0x40))?;
            buf.read_exact(&mut magic)?;
            if &magic == b"\x49\x4D\x45\x54" {
                // IMET with no build tag means the U8 archive should start at 0x600.
                buf.seek(SeekFrom::Start(0x600))?;
                buf.read_exact(&mut magic)?;
                if &magic != b"\x55\xAA\x38\x2D" {
                    return Err(U8Error::NotU8Data);
                }
                println!("ignoring IMET header at 0x40");
            }
            // Check for an IMET header that comes after a built tag.
            else {
                buf.seek(SeekFrom::Start(0x80))?;
                buf.read_exact(&mut magic)?;
                if &magic == b"\x49\x4D\x45\x54" {
                    // IMET with a build tag means the U8 archive should start at 0x600.
                    buf.seek(SeekFrom::Start(0x640))?;
                    buf.read_exact(&mut magic)?;
                    if &magic != b"\x55\xAA\x38\x2D" {
                        return Err(U8Error::NotU8Data);
                    }
                    println!("ignoring IMET header at 0x80");
                }
            }
        }
        // We're skipping the following values:
        // root_node_offset (u32): constant value, always 0x20
        // header_size (u32): we don't need this because we already know how long the string table is
        // data_offset (u32): we don't need this because nodes provide the absolute offset to their data
        // padding (u8 * 16): it's padding, I have nothing to say about it
        buf.seek(SeekFrom::Start(buf.position() + 28))?;
        // Manually read the root node, since we need its size anyway to know how many nodes there
        // are total.
        let root_node_type = buf.read_u8()?;
        let root_node_name_offset = buf.read_u24::<BigEndian>()?;
        let root_node_data_offset = buf.read_u32::<BigEndian>()?;
        let root_node_size = buf.read_u32::<BigEndian>()?;
        let root_node = U8Node {
            node_type: root_node_type,
            name_offset: root_node_name_offset,
            data_offset: root_node_data_offset,
            size: root_node_size,
        };
        // Create a vec of nodes, push the root node, and then iterate over the remaining number
        // of nodes in the file and push them to the vec.
        let mut u8_nodes: Vec<U8Node> = Vec::new();
        u8_nodes.push(root_node);
        for _ in 1..root_node_size {
            let node_type = buf.read_u8()?;
            let name_offset = buf.read_u24::<BigEndian>()?;
            let data_offset = buf.read_u32::<BigEndian>()?;
            let size = buf.read_u32::<BigEndian>()?;
            u8_nodes.push(U8Node { node_type, name_offset, data_offset, size })
        }
        // Iterate over the loaded nodes and load the file names and data associated with them.
        let base_name_offset = buf.position();
        let mut file_names = Vec::<String>::new();
        let mut file_data = Vec::<Vec<u8>>::new();
        for node in &u8_nodes {
            buf.seek(SeekFrom::Start(base_name_offset + node.name_offset as u64))?;
            let mut name_bin = Vec::<u8>::new();
            // Read the file name one byte at a time until we find a null byte.
            loop {
                let byte = buf.read_u8()?;
                if byte == b'\0' {
                    break;
                }
                name_bin.push(byte);
            }
            file_names.push(String::from_utf8(name_bin).map_err(|_| U8Error::InvalidFileName(base_name_offset + node.name_offset as u64))?.to_owned());
            // If this is a file node, read the data for the file.
            if node.node_type == 0 {
                buf.seek(SeekFrom::Start(node.data_offset as u64))?;
                let mut data = vec![0u8; node.size as usize];
                buf.read_exact(&mut data)?;
                file_data.push(data);
            } else {
                file_data.push(Vec::new());
            }
        }
        // Now that we have all the data loaded out of the file, assemble the tree of U8Items that
        // provides an actual map of the archive's data.
        let node_tree = U8Directory::new(String::new());
        let mut focused_node = Rc::clone(&node_tree);
        // This is the order of directory nodes we've traversed down.
        let mut parent_dirs: Vec<u32> = Vec::from([0]);
        for i in 0..u8_nodes.len() {
            match u8_nodes[i].node_type {
                1 => {
                    // Code for a directory node.
                    if u8_nodes[i].name_offset != 0 {
                        // If we're already at the correct level, push a new empty dir item to the
                        // item we're currently working on.
                        if u8_nodes[i].data_offset == *parent_dirs.last().unwrap() {
                            parent_dirs.push(i as u32);
                            U8Directory::add_dir(&focused_node, U8Directory::new(file_names[i].clone()));
                            focused_node = U8Directory::get_child_dir(&focused_node, &file_names[i]).unwrap();
                        }
                        // Otherwise, go back up the path until we're at the correct level.
                        else {
                            while u8_nodes[i].data_offset != *parent_dirs.last().unwrap() {
                                parent_dirs.pop();
                                let parent = focused_node.as_ref().borrow().get_parent().unwrap();
                                focused_node = parent;
                            }
                            parent_dirs.push(i as u32);
                            // Rebuild current working directory, and make sure all directories in the
                            // path exist.
                            U8Directory::add_dir(&focused_node, U8Directory::new(file_names[i].clone()));
                            focused_node = U8Directory::get_child_dir(&focused_node, &file_names[i]).unwrap()
                        }
                    }
                },
                0 => {
                    // Code for a file node.
                    U8Directory::add_file(&focused_node, U8File::new(file_names[i].clone(), file_data[i].clone()));
                },
                x => return Err(U8Error::InvalidNodeType(x, i))
            }
        }
        Ok(U8Archive {
            node_tree,
        })
    }
    
    pub fn from_tree(node_tree: &Rc<RefCell<U8Directory>>) -> Result<Self, U8Error> {
        Ok(U8Archive {
            node_tree: node_tree.clone(),
        })
    }
    
    fn pack_dir_recursive(file_names: &mut Vec<String>, file_data: &mut Vec<Vec<u8>>, u8_nodes: &mut Vec<U8Node>, current_node: &Rc<RefCell<U8Directory>>) {
        // For files, read their data into the file data list, add their name into the file name 
        // list, then calculate the offset for their file name and create a new U8Node() for them. 
        // 0 values for name/data offsets are temporary and are set later.
        let parent_node = u8_nodes.len() - 1;
        for file in &current_node.borrow().files {
            file_names.push(file.borrow().name.clone());
            file_data.push(file.borrow().data.clone());
            u8_nodes.push(U8Node { node_type: 0, name_offset: 0, data_offset: 0, size: file_data[u8_nodes.len()].len() as u32});
        }
        // For directories, add their name to the file name list, add empty data to the file data 
        // list, find the total number of files and directories inside the directory to calculate 
        // the final node included in it, then recursively call this function again on that 
        // directory to process it.
        for dir in &current_node.borrow().dirs {
            file_names.push(dir.borrow().name.clone());
            file_data.push(Vec::new());
            let max_node = u8_nodes.len() + current_node.borrow().count() + 1;
            u8_nodes.push(U8Node { node_type: 1, name_offset: 0, data_offset: parent_node as u32, size: max_node as u32});
            U8Archive::pack_dir_recursive(file_names, file_data, u8_nodes, dir)
        }
    }

    /// Dumps the data in a U8Archive instance back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, U8Error> {
        // We need to start by rebuilding a flat list of the nodes from the directory tree.
        let mut file_names: Vec<String> = vec![String::new()];
        let mut file_data: Vec<Vec<u8>> = vec![Vec::new()];
        let mut u8_nodes: Vec<U8Node> = Vec::new();
        u8_nodes.push(U8Node { node_type: 1, name_offset: 0, data_offset: 0, size: self.node_tree.borrow().count() as u32 });
        let root_node = Rc::clone(&self.node_tree);
        U8Archive::pack_dir_recursive(&mut file_names, &mut file_data, &mut u8_nodes, &root_node);
        // Header size starts at 0 because the header size starts with the nodes and does not
        // include the actual file header.
        let mut header_size: u32 = 0;
        // Add 12 bytes for each node, since that's how many bytes each one is made up of.
        for _ in 0..u8_nodes.len() {
            header_size += 12;
        }
        // Add the number of bytes used for each file/folder name in the string table.
        for file_name in &file_names {
            header_size += file_name.len() as u32 + 1
        }
        // The initial data offset is equal to the file header (32 bytes) + node data aligned to
        // 64 bytes.
        let data_offset: u32 = (header_size + 32 + 63) & !63;
        // Adjust all nodes to place file data in the same order as the nodes. For some reason
        // Nintendo-made U8 archives don't necessarily do this?
        let mut current_data_offset = data_offset;
        let mut current_name_offset: u32 = 0;
        for i in 0..u8_nodes.len() {
            if u8_nodes[i].node_type == 0 {
                u8_nodes[i].data_offset = (current_data_offset + 31) & !31;
                current_data_offset += (u8_nodes[i].size + 31) & !31;
            }
            // Calculate the name offsets, including the extra 1 for the NULL byte.
            u8_nodes[i].name_offset = current_name_offset;
            current_name_offset += file_names[i].len() as u32 + 1
        }
        // Begin writing file data.
        let mut buf: Vec<u8> = Vec::new();
        buf.write_all(b"\x55\xAA\x38\x2D")?;
        buf.write_u32::<BigEndian>(0x20)?; // The root node offset is always 0x20.
        buf.write_u32::<BigEndian>(header_size)?;
        buf.write_u32::<BigEndian>(data_offset)?;
        buf.write_all(&[0; 16])?;
        // Iterate over nodes and write them out.
        for node in &u8_nodes {
            buf.write_u8(node.node_type)?;
            buf.write_u24::<BigEndian>(node.name_offset)?;
            buf.write_u32::<BigEndian>(node.data_offset)?;
            buf.write_u32::<BigEndian>(node.size)?;
        }
        // Iterate over file names with a null byte at the end.
        for file_name in &file_names {
            buf.write_all(file_name.as_bytes())?;
            buf.write_u8(b'\0')?;
        }
        // Pad to the nearest multiple of 64 bytes.
        buf.resize((buf.len() + 63) & !63, 0);
        // Iterate over the file data and dump it. The file needs to be aligned to 32 bytes after
        // each write.
        for data in &file_data {
            buf.write_all(data)?;
            buf.resize((buf.len() + 31) & !31, 0);
        }
        Ok(buf)
    }
}
