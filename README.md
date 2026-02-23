![rustwii-banner](https://github.com/user-attachments/assets/08a7eea1-837e-4bce-939e-13c720b35226)
# rustwii

*Like rusty but it's rustwii because the Wii? Get it?*

[![Build rustwii](https://github.com/NinjaCheetah/rustwii/actions/workflows/rust.yml/badge.svg)](https://github.com/NinjaCheetah/rustwii/actions/workflows/rust.yml)

rustwii is a library and command line tool written in Rust for handling the various files and formats found on the Wii. rustwii is a port of my other library, [libWiiPy](https://github.com/NinjaCheetah/libWiiPy), which aims to accomplish the same goal in Python. At this point, rustwii should not be considered stable, however it offers most of the same core functionality as libWiiPy, and the rustwii CLI offers most of the same features as WiiPy. You can check which features are available and ready for use in both the library and the CLI below. The goal is for rustwii and libWiiPy to eventually have feature parity, with the rustwii CLI acting as a drop-in replacement for the (comparatively much less efficient) [WiiPy](https://github.com/NinjaCheetah/WiiPy) CLI.

There is currently no public documentation for rustwii, as I'm putting that off until I reach feature parity with libWiiPy so that the APIs are an equal level of stable. You can, however, reference the doc strings present on many of the structs and functions, and build them into basic documentation yourself (using `cargo doc --no-deps`). The [libWiiPy API docs](https://docs.ninjacheetah.dev) may also be helpful in some cases.

I'm still very new to Rust, so pardon any messy code or confusing API decisions you may find. libWiiPy started off like that, too.

### What's Included (Library-Side)
- Structs for parsing and editing WADs, TMDs, Tickets, and Certificate Chains
- Title Key and content encryption/decryption
- High-level Title struct (offering the same utility as libWiiPy's `Title`)
- Content addition/removal/replacing
- LZ77 compression/decompression
- ASH decompression
- U8 archive packing and unpacking
- NUS TMD/Ticket/certificate chain/content downloading

### What's Included (CLI-Side)
- WAD converting/packing/unpacking
- WAD content addition/removal/replacement
- NUS TMD/Ticket/Content/Title downloading
- LZ77 compression/decompression
- ASH decompression
- Fakesigning command for WADs/TMDs/Tickets
- Info command for WADs/TMDs/Tickets/U8 archives
- U8 archive packing/unpacking

To see specific usage information, check `rustwii --help` and `rustwii <command> --help`.

## Building
rustwii is a standard Rust crate. You'll need to have [Rust installed](https://www.rust-lang.org/learn/get-started), and then you can simply run:
```
cargo build --release
```
to compile the rustwii library and CLI. The CLI can then be found at `target/release/rustwii(.exe)`.

You can also download the latest nightly build from [GitHub Actions](https://github.com/NinjaCheetah/rustwii/actions).
