mod keccak;
use keccak::Keccak;
// use std::io::prelude::*;
use tokio::prelude::*;

#[tokio::main]
async fn main() {
    let mut keccak = Keccak::new();

    let file: Vec<u8> = tokio::fs::read("input.txt").await.unwrap();

    /*
    keccak.absorb_bits(1088, &file, 0b10, 2);
    println!("hash: {:x?}", keccak.squeeze(1088, 256 / 8));
    */
    // /*
    for _i in 0..1000000 {
        keccak.clear();
        keccak.absorb_bits(1088, &file, 0b10, 2);
        keccak.squeeze(1088, 256 / 8);
    }
    // */
    
    /*
    keccak.absorb(512, &file);
    let mut stdout = tokio::io::stdout();
    loop {
        stdout.write_all(&keccak.squeeze(512, 4096)).await.unwrap();
    }
    */
}
