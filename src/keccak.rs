use byterepr::ByteRepr;

pub const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];

pub const ROTATION_OFFSETS: [u8; 25] = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
];

pub const PI_TRANSFORM: [usize; 25] = [
    0, 10, 20, 5, 15,
    16, 1, 11, 21, 6,
    7, 17, 2, 12, 22,
    23, 8, 18, 3, 13,
    14, 24, 9, 19, 4
];

fn xytoi(x: u8, y: u8) -> usize {
    (y * 5 + x) as usize
}

fn xytoi_mod(x: u8, y: u8) -> usize {
    let mx = x % 5;
    let my = y % 5;
    (my * 5 + mx) as usize
}

fn itoxy(i: usize) -> (u8, u8) {
    (i as u8 % 5, i as u8 / 5)
}

fn rotl(n: u64, r: u8) -> u64 {
    if r == 0 { return n; }
    (n << r) | (n >> (64 - r))
}

pub type KeccakStateArray = [u64; 25];

pub fn keccakf(a: &mut KeccakStateArray) {
    for rc in ROUND_CONSTANTS.iter() { keccak_round(a, *rc); }
}

pub fn keccak_round(a: &mut KeccakStateArray, rc: u64) {
    let mut b = [0u64; 25];
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];

    // theta step
    for (x, val) in c.iter_mut().enumerate() {
        *val = a[xytoi(x as u8, 0)] ^ a[xytoi(x as u8, 1)] ^
            a[xytoi(x as u8, 2)] ^ a[xytoi(x as u8, 3)] ^ a[xytoi(x as u8, 4)]
    }
    for (x, val) in d.iter_mut().enumerate() {
        *val = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
    }
    for (i, val) in a.iter_mut().enumerate() {
        *val ^= d[i % 5];
    }

    // rho and pi steps
    for (from, val) in a.iter().enumerate() {
        b[PI_TRANSFORM[from]] = rotl(*val, ROTATION_OFFSETS[from]);
    }

    // chi step
    for (i, val) in a.iter_mut().enumerate() {
        let (x, y) = itoxy(i);
        *val = b[i] ^ (!b[xytoi_mod(x + 1, y)] & b[xytoi_mod(x + 2, y)]);
    }

    // iota step
    a[0] ^= rc;
}

pub fn pad_bits(block_size: usize, bytes: &Vec<u8>, bits: u8, bit_length: u8) -> Vec<u8> {
    let total_bit_length = bytes.len() * 8 + bit_length as usize;
    let mut padding_needed = block_size - (total_bit_length % block_size);
    if padding_needed == 1 { padding_needed += block_size; } // must have at least 2 bytes of padding
    let capacity = (total_bit_length + padding_needed) / 8;
    let mut padded_buf: Vec<u8> = Vec::with_capacity(capacity);
    padded_buf.resize(capacity, 0u8);
    padded_buf[0..bytes.len()].copy_from_slice(bytes);
    if bit_length != 0 {
        padded_buf[bytes.len()] = bits & (2u8.pow(bit_length as u32) - 1); 
    }
    if padding_needed != 0 {
        // pad10*1 first bit
        padded_buf[bytes.len()] |= 2u8.pow(bit_length as u32);
        // pad10*1 last bit
        let pad_end = padded_buf.len() - 1;
        padded_buf[pad_end] |= 0x80;
    }
    padded_buf
}

pub fn pad(block_size: usize, bytes: &Vec<u8>) -> Vec<u8> {
    pad_bits(block_size, bytes, 0, 0)
}

pub struct Keccak {
    state: KeccakStateArray
}

impl Keccak {
    pub fn new() -> Keccak {
        Keccak { state: [0u64; 25] }
    }

    pub fn keccakf(&mut self) {
        keccakf(&mut self.state);
    }

    pub fn absorb_bits(&mut self, r: usize, bytes: &Vec<u8>, bits: u8, bit_length: u8) {
        let padded = pad_bits(r, bytes, bits, bit_length);
        for i in (0..padded.len()).step_by(r / 8) {
            for j in 0..(r / 64)  {
                let start: usize = i + j * 8;
                self.state[j] ^= <u64 as ByteRepr>::from_le_bytes(&padded[start..(start + 8)]);
            }
            self.keccakf();
        }
    }

    pub fn absorb(&mut self, r: usize, bytes: &Vec<u8>) {
        self.absorb_bits(r, bytes, 0, 0);
    }

    pub fn squeeze(&mut self, r: usize, byte_len: usize) -> Vec<u8> {
        let byte_rate = r / 8;
        let buf_capacity: usize = ((byte_len + byte_rate - 1) / byte_rate) * byte_rate;
        let mut buf: Vec<u8> = Vec::with_capacity(buf_capacity);
        buf.resize(buf_capacity, 0u8);
        for i in (0..byte_len).step_by(byte_rate) {
            for j in 0..(r / 64) {
                let start: usize = i + j * 8;
                self.state[j].copy_to_le_bytes(&mut buf[start..(start + 8)]);
            }
            self.keccakf();
        }
        buf.truncate(byte_len);
        buf
    }

    pub fn clear(&mut self) {
        self.state = [0u64; 25];
    }
}
