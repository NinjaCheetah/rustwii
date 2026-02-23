// archive/ash.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the decompression routines used for the Wii's ASH compression scheme.
// May someday even include the compression routines! If I ever get around to it.
//
// This code is MESSY. It's a weird combination of Garhoogin's C implementation and my Python
// implementation of his C implementation. It should definitely be rewritten someday.

use std::io::{Cursor, Read};
use byteorder::{ByteOrder, BigEndian};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ASHError {
    #[error("this does not appear to be ASH-compressed data (missing magic number)")]
    NotASHData,
    #[error("ASH data is invalid")]
    InvalidData,
    #[error("LZ77 data is not in a valid format")]
    IO(#[from] std::io::Error),
}

const TREE_RIGHT: u32 = 0x80000000;
const TREE_LEFT: u32 = 0x40000000;
const TREE_VAL_MASK: u32 = 0x3FFFFFFF;

#[derive(Debug)]
struct ASHBitReader<'a> {
    src: &'a [u8],
    size: u32,
    src_pos: u32,
    word: u32,
    bit_capacity: u32,
}

fn ash_bit_reader_feed_word(reader: &mut ASHBitReader) -> Result<(), ASHError> {
    // Ensure that there's enough data to read en entire word, then if there is, read one.
    if reader.src_pos + 4 > reader.size {
        return Err(ASHError::InvalidData);
    }
    reader.word = BigEndian::read_u32(&reader.src[reader.src_pos as usize..reader.src_pos as usize + 4]);
    reader.bit_capacity = 0;
    reader.src_pos += 4;
    Ok(())
}

fn ash_bit_reader_init(src: &[u8], size: u32, startpos: u32) -> Result<ASHBitReader, ASHError> {
    // Load data into a bit reader, then have it read its first word.
    let mut reader = ASHBitReader {
        src,
        size,
        src_pos: startpos,
        word: 0,
        bit_capacity: 0,
    };
    ash_bit_reader_feed_word(&mut reader)?;
    Ok(reader)
}

fn ash_bit_reader_read_bit(reader: &mut ASHBitReader) -> Result<u32, ASHError> {
    // Reads the starting bit of the current word in the provided bit reader. If the capacity is at
    // 31, then we've shifted through the entire word, so a new one should be fed. If not, increase
    // the capacity by one and shift the current word left.
    let bit: u32 = reader.word >> 31;
    if reader.bit_capacity == 31 {
        ash_bit_reader_feed_word(reader)?;
    } else {
        reader.bit_capacity += 1;
        reader.word <<= 1;
    }
    Ok(bit)
}

fn ash_bit_reader_read_bits(reader: &mut ASHBitReader, num_bits: u32) -> Result<u32, ASHError> {
    // Reads a series of bytes from the current word in the supplied bit reader.
    let mut bits: u32;
    let next_bit = reader.bit_capacity + num_bits;
    if next_bit <= 32 {
        bits = reader.word >> (32 - num_bits);
        if next_bit != 32 {
            reader.word <<= num_bits;
            reader.bit_capacity += num_bits;
        } else {
            ash_bit_reader_feed_word(reader)?;
        }
    } else {
        bits = reader.word >> (32 - num_bits);
        ash_bit_reader_feed_word(reader)?;
        bits |= reader.word >> (64 - next_bit);
        reader.word <<= next_bit - 32;
        reader.bit_capacity = next_bit - 32;
    }
    Ok(bits)
}

fn ash_read_tree(reader: &mut ASHBitReader, width: u32, left_tree: &mut [u32], right_tree: &mut [u32]) -> Result<u32, ASHError> {
    // Read either the symbol or distance tree from the ASH file, and return the root of that tree.
    let mut work = vec![0; 2 * (1 << width)];
    let mut work_pos = 0;

    let mut r23: u32 = 1 << width;
    let mut tree_root: u32 = 0;
    let mut num_nodes: u32 = 0;
    loop {
        if ash_bit_reader_read_bit(reader)? != 0 {
            work[work_pos] = r23 | TREE_RIGHT;
            work_pos += 1;
            work[work_pos] = r23 | TREE_LEFT;
            work_pos += 1;
            num_nodes += 2;
            r23 += 1;
        } else {
            tree_root = ash_bit_reader_read_bits(reader, width)?;
            loop {
                work_pos -= 1;
                let node_value: u32 = work[work_pos];
                let idx = node_value & TREE_VAL_MASK;
                num_nodes -= 1;
                if (node_value & TREE_RIGHT) != 0 {
                    right_tree[idx as usize] = tree_root;
                    tree_root = idx;
                } else {
                    left_tree[idx as usize] = tree_root;
                    break;
                }
                if num_nodes == 0 {
                    break;
                }
            }
        }
        if num_nodes == 0 {
            break;
        }
    }
    Ok(tree_root)
}

fn ash_decompress_main(data: &[u8], size: u32, sym_bits: u32, dist_bits: u32) -> Result<Vec<u8>, ASHError> {
    let mut decompressed_size: u32 = BigEndian::read_u32(&data[0x4..0x8]) & 0x00FFFFFF;

    let mut buf = vec![0u8; decompressed_size as usize];
    let mut buf_pos: usize = 0;
    
    let mut reader1 = ash_bit_reader_init(data, size, BigEndian::read_u32(&data[0x8..0xC]))?;
    let mut reader2 = ash_bit_reader_init(data, size, 0xC)?;

    let sym_max: u32 = 1 << sym_bits;
    let dist_max: u32 = 1 << dist_bits;

    let mut sym_left_tree = vec![0u32; (2 * sym_max - 1) as usize];
    let mut sym_right_tree = vec![0u32; (2 * sym_max - 1) as usize];
    let mut dist_left_tree  = vec![0u32; (2 * dist_max - 1) as usize];
    let mut dist_right_tree = vec![0u32; (2 * dist_max - 1) as usize];

    let sym_root = ash_read_tree(&mut reader2, sym_bits, &mut sym_left_tree, &mut sym_right_tree)?;
    let dist_root = ash_read_tree(&mut reader1, dist_bits, &mut dist_left_tree, &mut dist_right_tree)?;
    
    // Main decompression loop.
    loop {
        let mut sym = sym_root;
        while sym >= sym_max {
            if ash_bit_reader_read_bit(&mut reader2)? != 0 {
                sym = sym_right_tree[sym as usize];
            } else {
                sym = sym_left_tree[sym as usize];
            }
        }
        if sym < 0x100 {
            buf[buf_pos] = sym as u8;
            buf_pos += 1;
            decompressed_size -= 1;
        } else {
            let mut dist_sym = dist_root;
            while dist_sym >= dist_max {
                if ash_bit_reader_read_bit(&mut reader1)? != 0 {
                    dist_sym = dist_right_tree[dist_sym as usize];
                } else {
                    dist_sym = dist_left_tree[dist_sym as usize];
                }
            }
            let mut copy_len = (sym - 0x100) + 3;
            let mut src_pos = buf_pos - dist_sym as usize - 1;
            if copy_len > decompressed_size {
                return Err(ASHError::InvalidData);
            }
    
            decompressed_size -= copy_len;
            while copy_len > 0 {
                buf[buf_pos] = buf[src_pos];
                buf_pos += 1;
                src_pos += 1;
                copy_len -= 1;
            }
        }
        if decompressed_size == 0 {
            break;
        }
    }
    Ok(buf)
}

/// Decompresses ASH-compressed data and returns the decompressed result.
pub fn decompress_ash(data: &[u8], sym_tree_bits: Option<u8>, dist_tree_bits: Option<u8>) -> Result<Vec<u8>, ASHError> {
    let mut buf = Cursor::new(data);
    // Check for magic "ASH0" to make sure that this is actually ASH data.
    let mut magic = [0u8; 4];
    buf.read_exact(&mut magic)?;
    if &magic != b"ASH0" {
        return Err(ASHError::NotASHData);
    }
    // Unwrap passed bit lengths or use defaults.
    let sym_tree_bits = sym_tree_bits.unwrap_or(9) as u32;
    let dist_tree_bits = dist_tree_bits.unwrap_or(11) as u32;
    let decompressed_data = ash_decompress_main(data, buf.get_ref().len() as u32, sym_tree_bits, dist_tree_bits)?;
    Ok(decompressed_data)
}
