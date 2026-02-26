// archive/u8.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the structures and methods required for parsing U8 archives.

use std::cmp::max;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
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
    pub dirs: Vec<U8Directory>,
    pub files: Vec<U8File>,
}

#[derive(Clone, Debug)]
pub struct U8File {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct U8Node {
    pub node_type: u8,
    pub name_offset: u32, // This is really type u24, so the most significant byte will be ignored.
    pub data_offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug)]
struct U8Reader {
    buf: Cursor<Box<[u8]>>,
    u8_nodes: Vec<U8Node>,
    index: usize,
    base_name_offset: u64
}

impl U8Reader {
    fn new(data: Box<[u8]>) -> Result<Self, U8Error> {
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
            // Check for an IMET header that comes after a build tag.
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
        // Save the base name offset for later.
        let base_name_offset = buf.position();

        Ok(Self {
            buf,
            u8_nodes,
            index: 0,
            base_name_offset
        })
    }

    fn file_name(&mut self, name_offset: u64) -> Result<String, U8Error> {
        self.buf.seek(SeekFrom::Start(self.base_name_offset + name_offset))?;
        let mut name_bin = Vec::<u8>::new();
        loop {
            let byte = self.buf.read_u8()?;
            if byte == b'\0' {
                break;
            }
            name_bin.push(byte);
        }
        Ok(String::from_utf8(name_bin)
            .map_err(|_| U8Error::InvalidFileName(self.base_name_offset + name_offset))?.to_owned()
        )
    }

    fn file_data(&mut self, data_offset: u64, size: usize) -> Result<Vec<u8>, U8Error> {
        self.buf.seek(SeekFrom::Start(data_offset))?;
        let mut data = vec![0u8; size];
        self.buf.read_exact(&mut data)?;
        Ok(data)
    }

    fn read_dir_recursive(&mut self) -> Result<U8Directory, U8Error> {
        let mut current_dir = U8Directory::new(self.file_name(self.u8_nodes[self.index].name_offset as u64)?);

        let current_dir_end = self.u8_nodes[self.index].size as usize;
        self.index += 1;
        while self.index < current_dir_end {
            match self.u8_nodes[self.index].node_type {
                1 => {
                    // Directory node, recursive over the child dir and then add it to the
                    // current one.
                    let child_dir = self.read_dir_recursive()?;
                    current_dir.add_dir(child_dir);
                },
                0 => {
                    // File node, add
                    current_dir.add_file(
                        U8File::new(
                            self.file_name(self.u8_nodes[self.index].name_offset as u64)?,
                            self.file_data(self.u8_nodes[self.index].data_offset as u64, self.u8_nodes[self.index].size as usize)?
                        )
                    );
                    self.index += 1;
                },
                x => return Err(U8Error::InvalidNodeType(x, self.index))
            }
        }

        Ok(current_dir)
    }
}

impl U8Directory {
    pub fn new(name: String) -> Self {
        Self {
            name,
            dirs: vec![],
            files: vec![]
        }
    }

    pub fn dirs(&self) -> &Vec<U8Directory> {
        &self.dirs
    }

    pub fn set_dirs(&mut self, dirs: Vec<U8Directory>) {
        self.dirs = dirs
    }

    pub fn files(&self) -> &Vec<U8File> {
        &self.files
    }

    pub fn set_files(&mut self, files: Vec<U8File>) {
        self.files = files
    }

    pub fn add_dir(&mut self, child: Self) -> &mut U8Directory {
        self.dirs.push(child);
        self.dirs.last_mut().unwrap()
    }

    pub fn add_file(&mut self, file: U8File) {
        self.files.push(file);
    }

    /// Creates a new U8 instance from the binary data of a U8 file.
    pub fn from_bytes(data: Box<[u8]>) -> Result<Self, U8Error> {
        let mut u8_reader = U8Reader::new(data)?;
        u8_reader.read_dir_recursive()
    }

    fn pack_dir_recursive(&self, file_names: &mut Vec<String>, file_data: &mut Vec<Vec<u8>>, u8_nodes: &mut Vec<U8Node>) {
        // For files, read their data into the file data list, add their name into the file name
        // list, then calculate the offset for their file name and create a new U8Node() for them.
        // 0 values for name/data offsets are temporary and are set later.
        let parent_node = u8_nodes.len() - 1;
        for file in &self.files {
            file_names.push(file.name.clone());
            file_data.push(file.data.clone());
            u8_nodes.push(U8Node { node_type: 0, name_offset: 0, data_offset: 0, size: file_data[u8_nodes.len()].len() as u32});
        }

        // For directories, add their name to the file name list, add empty data to the file data
        // list, find the total number of files and directories inside the directory to calculate
        // the final node included in it, then recursively call this function again on that
        // directory to process it.
        for dir in &self.dirs {
            file_names.push(dir.name.clone());
            file_data.push(Vec::new());
            let max_node = u8_nodes.len() + dir.count();
            u8_nodes.push(U8Node { node_type: 1, name_offset: 0, data_offset: parent_node as u32, size: max_node as u32});
            dir.pack_dir_recursive(file_names, file_data, u8_nodes);
        }
    }

    /// Dumps the data in a U8Archive instance back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, U8Error> {
        // We need to start by rebuilding a flat list of the nodes from the directory tree.
        let mut file_names: Vec<String> = vec![String::new()];
        let mut file_data: Vec<Vec<u8>> = vec![Vec::new()];
        let mut u8_nodes: Vec<U8Node> = Vec::new();
        u8_nodes.push(U8Node { node_type: 1, name_offset: 0, data_offset: 0, size: self.count() as u32 });
        self.pack_dir_recursive(&mut file_names, &mut file_data, &mut u8_nodes);

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
    
    fn count_recursive(&self) -> usize {
        let mut count = self.files.len() + self.dirs.len();

        for dir in self.dirs.iter() {
            count += dir.count_recursive();
        }
        count
    }
    
    pub fn count(&self) -> usize {
        1 + self.count_recursive()
    }
}

impl U8File {
    pub fn new(name: String, data: Vec<u8>) -> Self {
        Self {
            name,
            data
        }
    }
}
