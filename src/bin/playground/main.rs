// Sample file for testing rustii library stuff.

use std::fs;
use rustwii::title::{wad, cert};
use rustwii::title;
use rustwii::archive::u8;
// use rustii::title::content;

fn main() {
    let data = fs::read("ios9.wad").unwrap();
    let mut title = title::Title::from_bytes(&data).unwrap();

    let index = title::iospatcher::ios_find_module(String::from("ES:"), &title).unwrap();
    println!("ES index: {}", index);

    let patch_count = title::iospatcher::ios_patch_sigchecks(&mut title, index).unwrap();
    println!("patches applied: {}", patch_count);

    println!("Title ID from WAD via Title object: {}", hex::encode(title.tmd.title_id()));

    let wad = wad::WAD::from_bytes(&data).unwrap();
    println!("size of tmd: {:?}", wad.tmd().len());
    println!("num content records: {:?}", title.tmd.content_records().len());
    println!("first record data: {:?}", title.tmd.content_records().first().unwrap());
    println!("TMD is fakesigned: {:?}",title.tmd.is_fakesigned());

    println!("title version from ticket is: {:?}", title.ticket.title_version());
    println!("title key (enc): {:?}", title.ticket.title_key());
    println!("title key (dec): {:?}", title.ticket.title_key_dec());
    println!("ticket is fakesigned: {:?}", title.ticket.is_fakesigned());

    println!("title is fakesigned: {:?}", title.is_fakesigned());

    let cert_chain = &title.cert_chain;
    println!("cert chain OK");
    let result = cert::verify_ca_cert(&cert_chain.ca_cert()).unwrap();
    println!("CA cert {} verified successfully: {}", cert_chain.ca_cert().child_cert_identity(), result);

    let result = cert::verify_child_cert(&cert_chain.ca_cert(), &cert_chain.tmd_cert()).unwrap();
    println!("TMD cert {} verified successfully: {}", cert_chain.tmd_cert().child_cert_identity(), result);
    let result = cert::verify_tmd(&cert_chain.tmd_cert(), &title.tmd).unwrap();
    println!("TMD verified successfully: {}", result);

    let result = cert::verify_child_cert(&cert_chain.ca_cert(), &cert_chain.ticket_cert()).unwrap();
    println!("Ticket cert {} verified successfully: {}", cert_chain.ticket_cert().child_cert_identity(), result);
    let result = cert::verify_ticket(&cert_chain.ticket_cert(), &title.ticket).unwrap();
    println!("Ticket verified successfully: {}", result);

    let result = title.verify().unwrap();
    println!("full title verified successfully: {}", result);

    let u8_archive = u8::U8Directory::from_bytes(fs::read("testu8.arc").unwrap().into_boxed_slice()).unwrap();
    println!("{:#?}", u8_archive);
    
    // let mut content_map = content::SharedContentMap::from_bytes(&fs::read("content.map").unwrap()).unwrap();
    // content_map.add(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    // fs::write("new.map", content_map.to_bytes().unwrap()).unwrap();
}
