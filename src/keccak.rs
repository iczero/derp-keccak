pub const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

pub type KeccakStateArray = [u64; 25];

pub fn keccakf(a: &mut KeccakStateArray, rounds: usize) {
    for rc in ROUND_CONSTANTS.iter().skip(24 - rounds) {
        keccak_round(a, *rc);
    }
}

pub fn keccak_round(a: &mut KeccakStateArray, rc: u64) {
    let mut b = [0u64; 25];
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];

    // theta step
    for i in 0..5 {
        c[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
    }

    for i in 0..5 {
        d[i] = c[(i + 1) % 5].rotate_left(1);
        d[i] ^= c[(i + 4) % 5];
    }

    for i in 0..25 {
        a[i] ^= d[i % 5];
    }

    // rho and pi steps
    b[0] = a[0].rotate_left(0);
    b[10] = a[1].rotate_left(1);
    b[20] = a[2].rotate_left(62);
    b[5] = a[3].rotate_left(28);
    b[15] = a[4].rotate_left(27);

    b[16] = a[5].rotate_left(36);
    b[1] = a[6].rotate_left(44);
    b[11] = a[7].rotate_left(6);
    b[21] = a[8].rotate_left(55);
    b[6] = a[9].rotate_left(20);

    b[7] = a[10].rotate_left(3);
    b[17] = a[11].rotate_left(10);
    b[2] = a[12].rotate_left(43);
    b[12] = a[13].rotate_left(25);
    b[22] = a[14].rotate_left(39);

    b[23] = a[15].rotate_left(41);
    b[8] = a[16].rotate_left(45);
    b[18] = a[17].rotate_left(15);
    b[3] = a[18].rotate_left(21);
    b[13] = a[19].rotate_left(8);

    b[14] = a[20].rotate_left(18);
    b[24] = a[21].rotate_left(2);
    b[9] = a[22].rotate_left(61);
    b[19] = a[23].rotate_left(56);
    b[4] = a[24].rotate_left(14);

    // chi step
    a[0] = (!b[1] & b[2]) ^ b[0];
    a[1] = (!b[2] & b[3]) ^ b[1];
    a[2] = (!b[3] & b[4]) ^ b[2];
    a[3] = (!b[4] & b[0]) ^ b[3];
    a[4] = (!b[0] & b[1]) ^ b[4];

    a[5] = (!b[6] & b[7]) ^ b[5];
    a[6] = (!b[7] & b[8]) ^ b[6];
    a[7] = (!b[8] & b[9]) ^ b[7];
    a[8] = (!b[9] & b[5]) ^ b[8];
    a[9] = (!b[5] & b[6]) ^ b[9];

    a[10] = (!b[11] & b[12]) ^ b[10];
    a[11] = (!b[12] & b[13]) ^ b[11];
    a[12] = (!b[13] & b[14]) ^ b[12];
    a[13] = (!b[14] & b[10]) ^ b[13];
    a[14] = (!b[10] & b[11]) ^ b[14];

    a[15] = (!b[16] & b[17]) ^ b[15];
    a[16] = (!b[17] & b[18]) ^ b[16];
    a[17] = (!b[18] & b[19]) ^ b[17];
    a[18] = (!b[19] & b[15]) ^ b[18];
    a[19] = (!b[15] & b[16]) ^ b[19];

    a[20] = (!b[21] & b[22]) ^ b[20];
    a[21] = (!b[22] & b[23]) ^ b[21];
    a[22] = (!b[23] & b[24]) ^ b[22];
    a[23] = (!b[24] & b[20]) ^ b[23];
    a[24] = (!b[20] & b[21]) ^ b[24];

    // iota step
    a[0] ^= rc;
}

pub fn pad10_1(block_size_bits: usize, bytes: &[u8], bits: u8, bit_length: u8) -> Vec<u8> {
    let total_bit_length = bytes.len() * 8 + bit_length as usize;
    let mut padding_needed = block_size_bits - (total_bit_length % block_size_bits);
    if padding_needed < 2 {
        // must have at least 2 bytes of padding
        padding_needed += block_size_bits;
    }

    // allocate buffer for padded contents
    let capacity = (total_bit_length + padding_needed) / 8;
    let mut padded_buf: Vec<u8> = Vec::with_capacity(capacity);
    padded_buf.resize(capacity, 0u8);
    // copy original block(s)
    padded_buf[0..bytes.len()].copy_from_slice(bytes);

    // if additional bits are defined, add them
    if bit_length != 0 {
        padded_buf[bytes.len()] = bits & (2u8.pow(bit_length as u32) - 1);
    }
    // pad10*1 first bit
    padded_buf[bytes.len()] |= 2u8.pow(bit_length as u32);
    // pad10*1 last bit
    let pad_end = padded_buf.len() - 1;
    padded_buf[pad_end] |= 0x80;
    padded_buf
}

pub struct Keccak {
    pub state: KeccakStateArray,
    pub rounds: usize,
}

impl Keccak {
    pub fn new() -> Keccak {
        Keccak {
            state: [0u64; 25],
            rounds: 24,
        }
    }

    pub fn with_rounds(rounds: usize) -> Keccak {
        assert!(rounds <= ROUND_CONSTANTS.len(), "too many rounds");
        Keccak {
            state: [0u64; 25],
            rounds,
        }
    }

    pub fn keccakf(&mut self) {
        keccakf(&mut self.state, self.rounds);
    }

    // invariants for the following two functions:
    // - buf.len() must be a multiple of 8 bytes
    // - buf.len() must not be more than 200 bytes (length of internal state)
    // additionally, you MUST call keccakf() or everything will be broken
    // (see absorb_direct_unchecked and squeeze_direct_unchecked)

    pub unsafe fn state_insert_bytes_unchecked(&mut self, buf: &[u8]) {
        for (idx, val) in buf.as_chunks_unchecked::<8>().iter().enumerate() {
            let pos = self.state.get_unchecked_mut(idx);
            *pos = *pos ^ u64::from_le_bytes(*val);
        }
    }

    pub unsafe fn state_extract_bytes_unchecked(&mut self, buf: &mut [u8]) {
        for i in 0..buf.len() / 8 {
            let byte_idx = i * 8;
            buf.get_unchecked_mut(byte_idx..byte_idx + 8)
                .copy_from_slice(&self.state.get_unchecked(i).to_le_bytes());
        }
    }

    pub unsafe fn absorb_block_unchecked(&mut self, buf: &[u8]) {
        self.state_insert_bytes_unchecked(buf);
        self.keccakf();
    }

    pub fn absorb_block(&mut self, r: usize, buf: &[u8]) {
        assert!(r % 64 == 0, "bitrate must be a multiple of 64");
        assert!(r <= 1600, "bitrate exceeds state length");
        assert!(buf.len() == r / 8, "incorrect block size for bitrate");
        unsafe {
            self.absorb_block_unchecked(buf);
        }
    }

    pub fn absorb_padded(&mut self, r: usize, bytes: &[u8], bits: u8, bit_length: u8) {
        assert!(r % 64 == 0, "bitrate must be a multiple of 64");
        assert!(r <= 1600, "bitrate exceeds state length");

        // safety note: all following uses of absorb_direct_unchecked ensure valid input
        if bytes.len() == 0 {
            // we were told to absorb nothing, absorb padding block
            let pad_block = pad10_1(r, &[], bits, bit_length);
            unsafe {
                self.absorb_block_unchecked(&pad_block);
            }
            return;
        }

        let blocks = bytes.len().div_ceil(r / 8);
        // absorb without padding until last block
        for i in 0..blocks - 1 {
            unsafe {
                let byte_idx = i * r / 8;
                let block = &bytes[byte_idx..byte_idx + r / 8];
                self.absorb_block_unchecked(block);
            }
        }
        // pad and absorb last block
        let padded = pad10_1(r, bytes, bits, bit_length);
        for block in padded.chunks(r / 8) {
            unsafe {
                self.absorb_block_unchecked(block);
            }
        }
    }

    pub unsafe fn squeeze_block_unchecked(&mut self, buf: &mut [u8]) {
        self.state_extract_bytes_unchecked(buf);
        self.keccakf();
    }

    pub fn squeeze_block(&mut self, r: usize, dest: &mut [u8]) {
        assert!(r % 64 == 0, "bitrate must be a multiple of 64");
        assert!(r <= 1600, "bitrate exceeds state length");
        assert!(
            dest.len() == r / 8,
            "destination length does not match bitrate"
        );
        unsafe {
            self.state_extract_bytes_unchecked(dest);
        }
        self.keccakf();
    }

    pub fn squeeze_into(&mut self, r: usize, dest: &mut [u8]) {
        assert!(r % 64 == 0, "bitrate must be a multiple of 64");
        assert!(r <= 1600, "bitrate exceeds state length");
        let byte_rate = r / 8;
        let mut index = 0;
        while index + byte_rate <= dest.len() {
            unsafe {
                self.squeeze_block_unchecked(&mut dest[index..index + byte_rate]);
            }
            index += byte_rate;
        }
        if index < dest.len() {
            // last block (partial)
            assert!((&dest[index..]).len() < byte_rate);
            unsafe {
                self.squeeze_block_unchecked(&mut dest[index..]);
            }
        }
    }

    pub fn squeeze_vec(&mut self, r: usize, byte_length: usize) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::with_capacity(byte_length);
        vec.resize(byte_length, 0);
        self.squeeze_into(r, &mut vec);
        vec
    }

    pub fn duplex_block(&mut self, r: usize, squeeze_to: &mut [u8], absorb_from: &[u8]) {
        assert!(r % 64 == 0, "bitrate must be a multiple of 64");
        assert!(r <= 1600, "bitrate exceeds state length");
        assert!(
            squeeze_to.len() == r / 8,
            "destination length does not match bitrate"
        );
        assert!(
            absorb_from.len() == r / 8,
            "source length does not match bitrate"
        );
        unsafe {
            self.state_extract_bytes_unchecked(squeeze_to);
            self.state_insert_bytes_unchecked(absorb_from);
        }
        self.keccakf();
    }

    pub fn reset(&mut self) {
        self.state = [0u64; 25];
    }
}
