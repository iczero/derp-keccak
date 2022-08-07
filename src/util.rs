const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub fn bytes_to_hex(buf: &[u8]) -> String {
    let mut out = String::with_capacity(buf.len() * 2);
    for i in 0..buf.len() {
        out.push(HEX_DIGITS[(buf[i] >> 4) as usize]);
        out.push(HEX_DIGITS[(buf[i] & 0xf) as usize]);
    }
    out
}
