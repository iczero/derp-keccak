use crate::util::bytes_to_hex;
use crate::Keccak;

pub struct DigestBytes<const D: usize> {
    pub data: [u8; D],
}

pub trait Digest {
    fn hex(&self) -> String;
}

impl<const D: usize> Digest for DigestBytes<D> {
    fn hex(&self) -> String {
        bytes_to_hex(&self.data)
    }
}

// type parameters:
// CAPACITY: capacity (512 bits for sha3-256)
// BUFFER_LEN: buffer length (must be equivalent to byte length of bitrate)
// DIGEST_BYTES: digest length in bytes
// PAD_BITS: extra bits in padding
// PAD_BITS_LEN: how many bits in PAD_BITS
pub struct KeccakHashState<
    const CAPACITY: usize,
    const BUFFER_LEN: usize,
    const DIGEST_BYTES: usize,
    const PAD_BITS: u8,
    const PAD_BITS_LEN: u8,
> {
    pub state: Keccak,
    pub buffer: [u8; BUFFER_LEN],
    pub buffer_pos: usize,
    _private_construct: (),
}

pub trait KeccakHash {
    type DigestType: Digest;

    const CAPACITY: usize;
    const RATE: usize;
    const CAPACITY_BYTES: usize;
    const RATE_BYTES: usize;

    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::DigestType;
}

impl<
        const C: usize,
        const BUFFER_LEN: usize,
        const DIGEST_BYTES: usize,
        const PAD_BITS: u8,
        const PAD_BITS_LEN: u8,
    > KeccakHashState<C, BUFFER_LEN, DIGEST_BYTES, PAD_BITS, PAD_BITS_LEN>
{
    pub fn new() -> KeccakHashState<C, BUFFER_LEN, DIGEST_BYTES, PAD_BITS, PAD_BITS_LEN> {
        assert!(C % 64 == 0, "capacity must be a multiple of 64 bits");
        assert!(
            (1600 - C) / 8 == BUFFER_LEN,
            "provided capacity does not match buffer length"
        );
        assert!(DIGEST_BYTES * 8 <= 1600, "digest length too long");
        KeccakHashState {
            state: Keccak::new(),
            buffer: [0u8; BUFFER_LEN],
            buffer_pos: 0,
            _private_construct: (),
        }
    }
}

impl<
        const C: usize,
        const BUFFER_LEN: usize,
        const DIGEST_BYTES: usize,
        const PAD_BITS: u8,
        const PAD_BITS_LEN: u8,
    > KeccakHash for KeccakHashState<C, BUFFER_LEN, DIGEST_BYTES, PAD_BITS, PAD_BITS_LEN>
{
    type DigestType = DigestBytes<DIGEST_BYTES>;

    const CAPACITY: usize = C;
    const RATE: usize = 1600 - Self::CAPACITY;
    const CAPACITY_BYTES: usize = Self::CAPACITY / 8;
    const RATE_BYTES: usize = Self::RATE / 8;

    fn update(&mut self, data: &[u8]) {
        let mut index: usize = 0;
        if self.buffer_pos + data.len() >= self.buffer.len() {
            if self.buffer_pos > 0 {
                index += self.buffer.len() - self.buffer_pos;
                // data exists in buffer, fill remainder
                self.buffer[self.buffer_pos..].copy_from_slice(&data[0..index]);
                // absorb buffer
                unsafe {
                    self.state.absorb_block_unchecked(&self.buffer);
                }
                self.buffer_pos = 0;
            }
        } else {
            // data fits entirely in current buffer
            self.buffer[self.buffer_pos..self.buffer_pos + data.len()].copy_from_slice(&data);
            self.buffer_pos += data.len();
            return;
        }

        // no buffered data exists, absorb full blocks from data
        while index + Self::RATE_BYTES <= data.len() {
            unsafe {
                self.state
                    .absorb_block_unchecked(&data[index..index + Self::RATE_BYTES]);
            }
            index += Self::RATE_BYTES;
        }

        // if excess data exists, push to buffer
        if data.len() - index > 0 {
            let remaining = &data[index..];
            self.buffer[0..remaining.len()].copy_from_slice(remaining);
            self.buffer_pos = remaining.len();
        }
    }

    fn finalize(mut self) -> DigestBytes<DIGEST_BYTES> {
        // write buffer to keccak (or padding block if buffer is empty)
        self.state.absorb_padded(
            Self::RATE,
            &self.buffer[0..self.buffer_pos],
            PAD_BITS,
            PAD_BITS_LEN,
        );
        let digest_bytes = self.state.squeeze_many(Self::RATE, DIGEST_BYTES);
        let mut digest = DigestBytes {
            data: [0u8; DIGEST_BYTES],
        };
        digest.data.copy_from_slice(&digest_bytes);
        digest
    }
}

// SHA-3 instances (SHA3-224 not supported because absurd reasons)
pub type SHA3_256 = KeccakHashState<512, 136, 32, 0b10, 2>;
pub type SHA3_384 = KeccakHashState<768, 104, 48, 0b10, 2>;
pub type SHA3_512 = KeccakHashState<1024, 72, 64, 0b10, 2>;

// fixed length SHAKE instances
pub type SHAKE128_256 = KeccakHashState<256, 168, 32, 0b1111, 4>;
pub type SHAKE256_512 = KeccakHashState<512, 136, 64, 0b1111, 4>;
