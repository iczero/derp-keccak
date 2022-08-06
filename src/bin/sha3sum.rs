use tokio;
use tokio::io::{BufReader, AsyncReadExt};
use anyhow;

use keccak::Keccak;

const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f'
];
// ecks dee
fn buf_to_string(buf: &[u8]) -> String {
    let mut out = String::with_capacity(buf.len() * 2);
    for i in 0..buf.len() {
        out.push(HEX_DIGITS[(buf[i] >> 4) as usize]);
        out.push(HEX_DIGITS[(buf[i] & 0xf) as usize]);
    }
    out
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut keccak = Keccak::new();

    let mut stdin = BufReader::new(tokio::io::stdin());
    let bitrate = 1088;
    let byterate = bitrate / 8;
    let mut buf: Vec<u8> = Vec::with_capacity(byterate);
    buf.resize(byterate, 0);

    let mut read_offset: usize = 0;
    loop {
        let len = stdin.read(&mut buf[read_offset..]).await?;
        if len + read_offset == byterate {
            unsafe { keccak.absorb_direct_unchecked(&buf); }
            read_offset = 0;
        } else if len == 0 {
            keccak.absorb_bits(bitrate, &buf[0..read_offset], 0b10, 2);
            break;
        } else {
            read_offset += len;
        }
    }

    let out = keccak.squeeze(bitrate, 256 / 8);
    println!("{}", buf_to_string(&out));
    Ok(())
}
