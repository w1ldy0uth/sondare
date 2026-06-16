pub fn add_slice(sum: &mut u32, data: &[u8]) {
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        *sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        *sum += (b as u32) << 8;
    }
}

pub fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn compute(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    add_slice(&mut sum, data);
    fold(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zeros_yields_zero_complement() {
        // checksum of all-zero data: fold(0) = !0 = 0xffff
        assert_eq!(compute(&[0u8; 20]), 0xffff);
    }

    #[test]
    fn odd_length_padded() {
        // single 0x01 byte -> sum = 0x0100, ~0x0100 = 0xfeff
        assert_eq!(compute(&[0x01]), 0xfeff);
    }
}
