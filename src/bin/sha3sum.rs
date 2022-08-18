#![feature(slice_as_chunks)]
use derp_keccak::hash::{
    Digest, KeccakHash, SHA3_256, SHA3_384, SHA3_512, SHAKE128_256, SHAKE256_512,
};
use derp_keccak::util::bytes_to_hex;
use derp_keccak::Keccak;
use std::io::{BufReader, Read};

fn main_old() -> anyhow::Result<()> {
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
                keccak.absorb_block_unchecked(&buf);
            }
            read_offset = 0;
        } else if len == 0 {
            keccak.absorb_padded(bitrate, &buf[0..read_offset], 0b10, 2);
            break;
        } else {
            read_offset += len;
        }
    }

    let out = keccak.squeeze_many(bitrate, 256 / 8);
    println!("{}", bytes_to_hex(&out));
    Ok(())
}

fn main_keccakhash<T: KeccakHash>(mut hash: T) -> anyhow::Result<()> {
    let mut stdin = std::io::stdin();
    const READ_SIZE: usize = 16384;
    let mut buf: Vec<u8> = Vec::with_capacity(READ_SIZE);
    buf.resize(READ_SIZE, 0);

    loop {
        let len = stdin.read(&mut buf)?;
        if len == 0 {
            break;
        }
        hash.update(&buf[0..len]);
    }

    println!("{}", hash.finalize().hex());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    if args.get(1) == None {
        main_keccakhash(SHA3_256::new())?;
    } else {
        match args[1].as_str() {
            "256" => {
                main_keccakhash(SHA3_256::new())?;
            }
            "384" => {
                main_keccakhash(SHA3_384::new())?;
            }
            "512" => {
                main_keccakhash(SHA3_512::new())?;
            }
            "shake128" => {
                main_keccakhash(SHAKE128_256::new())?;
            }
            "shake256" => {
                main_keccakhash(SHAKE256_512::new())?;
            }
            "old" => {
                main_old()?;
            }
            _ => {
                eprintln!("invalid hash length");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // TODO: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
}
