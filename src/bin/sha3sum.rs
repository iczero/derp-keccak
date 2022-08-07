#![feature(slice_as_chunks)]
use derp_keccak::util::bytes_to_hex;
use derp_keccak::Keccak;
use std::io::{BufReader, Read};

fn main() -> anyhow::Result<()> {
    let mut keccak = Keccak::new();

    let mut stdin = BufReader::new(std::io::stdin());
    let bitrate = 1088;
    let byterate = bitrate / 8;
    let mut buf: Vec<u8> = Vec::with_capacity(byterate);
    buf.resize(byterate, 0);

    let mut read_offset: usize = 0;
    loop {
        let len = stdin.read(&mut buf[read_offset..])?;
        if len + read_offset == byterate {
            unsafe {
                keccak.absorb_direct_unchecked(&buf);
            }
            read_offset = 0;
        } else if len == 0 {
            keccak.absorb_padded(bitrate, &buf[0..read_offset], 0b10, 2);
            break;
        } else {
            read_offset += len;
        }
    }

    let out = keccak.squeeze(bitrate, 256 / 8);
    println!("{}", bytes_to_hex(&out));
    Ok(())
}

#[cfg(test)]
mod tests {
    // TODO: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
}
