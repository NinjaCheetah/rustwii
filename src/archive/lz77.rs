// archive/lz77.rs from ruswtii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustwii
//
// Implements the compression and decompression routines used for the Wii's LZ77 compression scheme.

use std::cmp::min;
use std::io::{Cursor, Read, Write, Seek, SeekFrom};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LZ77Error {
    #[error("compression is type `{0}` but only 0x10 is supported")]
    InvalidCompressionType(u8),
    #[error("LZ77 data is not in a valid format")]
    IO(#[from] std::io::Error),
}

const LZ_MIN_DISTANCE: usize = 0x01; // Minimum distance for each reference.
const LZ_MAX_DISTANCE: usize = 0x1000; // Maximum distance for each reference.
const LZ_MIN_LENGTH: usize = 0x03; // Minimum length for each reference.
const LZ_MAX_LENGTH: usize = 0x12; // Maximum length for each reference.

#[derive(Clone)]
struct LZNode {
    dist: usize,
    len: usize,
    weight: usize,
}

fn compress_compare_bytes(buf: &[u8], offset1: usize, offset2: usize, abs_len_max: usize) -> usize {
    // Compare bytes up to the maximum length we can match. Start by comparing the first 3 bytes, 
    // since that's the minimum match length and this allows for a more optimized early exit.
    let mut num_matched: usize = 0;
    while num_matched < abs_len_max {
        if buf[offset1 + num_matched] != buf[offset2 + num_matched] {
            break
        }
        num_matched += 1
    }
    num_matched
}

fn compress_search_matches(buf: &[u8], pos: usize) -> (usize, usize) {
    let bytes_left = buf.len() - pos;
    // Default to only looking back 4096 bytes, unless we've moved fewer than 4096 bytes, in which 
    // case we should only look as far back as we've gone.
    let max_dist = min(LZ_MAX_DISTANCE, pos);
    // Default to only matching up to 18 bytes, unless fewer than 18 bytes remain, in which case 
    // we can only match up to that many bytes.
    let max_len = min(LZ_MAX_LENGTH, bytes_left);
    // Log the longest match we found and its offset.
    let (mut biggest_match, mut biggest_match_pos) = (0, 0);
    // Search for matches.
    for i in LZ_MIN_DISTANCE..(max_dist + 1) {
        let num_matched = compress_compare_bytes(buf, pos - i, pos, max_len);
        if num_matched > biggest_match {
            biggest_match = num_matched;
            biggest_match_pos = i;
            if biggest_match == max_len {
                break;
            }
        }
    }
    (biggest_match, biggest_match_pos)
}

fn compress_node_is_ref(node: LZNode) -> bool {
    node.len >= LZ_MIN_LENGTH
}

fn compress_get_node_cost(length: usize) -> usize {
    let num_bytes = if length >= LZ_MIN_LENGTH {
        2
    } else {
        1
    };
    1 + (num_bytes * 8)
}

/// Compresses data using the Wii's LZ77 compression algorithm and returns the compressed result.
pub fn compress_lz77(data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
    // Optimized compressor based around a node graph that finds optimal string matches.
    let mut nodes = vec![LZNode { dist: 0, len: 0, weight: 0 }; data.len()];
    // Iterate over the uncompressed data, starting from the end.
    let mut pos = data.len();
    while pos > 0 {
        pos -= 1;
        // Limit the maximum search length when we're near the end of the file.
        let mut max_search_len = min(LZ_MAX_LENGTH, data.len() - pos);
        if max_search_len < LZ_MIN_DISTANCE {
            max_search_len = 1;
        }
        // Initialize as 1 for each, since that's all we could use if we weren't compressing.
        let (mut length, mut dist) = (1, 1);
        if max_search_len >= LZ_MIN_LENGTH {
            (length, dist) = compress_search_matches(data, pos);
        }
        // Treat as direct bytes if it's too short to copy.
        if length == 0 || length < LZ_MIN_LENGTH {
            length = 1;
        }
        // If the node goes to the end of the file, the weight is the cost of the node.
        if (pos + length) == data.len() {
            nodes[pos].len = length;
            nodes[pos].dist = dist;
            nodes[pos].weight = compress_get_node_cost(length);
        }
        // Otherwise, search for possible matches and determine the one with the best cost.
        else {
            let mut weight_best = u32::MAX as usize;
            let mut len_best = 1;
            while length > 0 {
                let weight_next = nodes[pos + length].weight;
                let weight = compress_get_node_cost(length) + weight_next;
                if weight < weight_best {
                    len_best = length;
                    weight_best = weight;
                }
                length -= 1;
                if length != 0 && length < LZ_MIN_LENGTH {
                    length = 1;
                }
            }
            nodes[pos].len = len_best;
            nodes[pos].dist = dist;
            nodes[pos].weight = weight_best;
        }
    }
    // Write out compressed data now that we've done our calculations.
    let mut buf = Cursor::new(Vec::new());
    buf.write_all(b"LZ77\x10")?;
    buf.write_u24::<LittleEndian>(data.len() as u32)?;
    let mut src_pos = 0;
    while src_pos < data.len() {
        let mut flag = 0;
        let flag_pos = buf.position();
        buf.write_u8(b'\x00')?;  // Reserve a byte for the flag.
        let mut i = 0;
        while i < 8 && src_pos < data.len() {
            let current_node = nodes[src_pos].clone();
            let length = current_node.len;
            let dist = current_node.dist;
            // This is a reference node.
            if compress_node_is_ref(current_node) {
                let encoded = ((((length - LZ_MIN_LENGTH) & 0xF) << 12) | ((dist - LZ_MIN_DISTANCE) & 0xFFF)) as u16;
                buf.write_u16::<BigEndian>(encoded)?;
                flag |= 1 << (7 - i);
            }
            // This is a direct copy node.
            else {
                buf.write_all(&data[src_pos..src_pos + 1])?;
            }
            src_pos += length;
            i += 1
        }
        pos = buf.position() as usize;
        buf.seek(SeekFrom::Start(flag_pos))?;
        buf.write_u8(flag)?;
        buf.seek(SeekFrom::Start(pos as u64))?;
    }
    Ok(buf.into_inner())
}

/// Decompresses LZ77-compressed data and returns the decompressed result.
pub fn decompress_lz77(data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
    let mut buf = Cursor::new(data);
    // Check for magic so that we know where to start. If the compressed data was sourced from
    // inside of something, it may not have the magic and instead starts immediately at 0.
    let mut magic = [0u8; 4];
    buf.read_exact(&mut magic)?;
    if &magic != b"LZ77" {
        buf.seek(SeekFrom::Start(0))?;
    }
    // Read one byte to ensure this is compression type 0x10. Nintendo used other types, but only
    // 0x10 was supported on the Wii.
    let compression_type = buf.read_u8()?;
    if compression_type != 0x10 {
        return Err(LZ77Error::InvalidCompressionType(compression_type));
    }
    // Read the decompressed size, which is stored as 3 LE bytes for some reason.
    let decompressed_size = buf.read_u24::<LittleEndian>()? as usize;
    let mut out_buf = vec![0u8; decompressed_size];
    let mut pos = 0;
    while pos < decompressed_size {
        let flag = buf.read_u8()?;
        // Read bits in flag from most to least significant.
        let mut x = 7;
        while x >= 0 {
            // Prevents buffer overrun if the final flag is only partially used.
            if pos >= decompressed_size {
                break;
            }
            // Bit is 1, which is a reference to previous data in the file.
            if flag & (1 << x) != 0 {
                let reference = buf.read_u16::<BigEndian>()?;
                let length = 3 + ((reference >> 12) & 0xF);
                let mut offset = pos - (reference & 0xFFF) as usize - 1;
                for _ in 0..length {
                    out_buf[pos] = out_buf[offset];
                    pos += 1;
                    offset += 1;
                    // Avoids a buffer overrun if the copy length would extend past the end of the file.
                    if pos >= decompressed_size {
                        break;
                    }
                }
            } 
            // Bit is 0, which is a direct byte copy.
            else {
                out_buf[pos] = buf.read_u8()?;
                pos += 1;
            }
            x -= 1;
        }
    }
    Ok(out_buf)
}
