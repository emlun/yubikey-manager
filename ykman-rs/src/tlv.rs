use std::convert::TryInto;

fn add_u128_leading_zeroes(bytes: &[u8], len: usize) -> [u8; 16] {
    let mut padded: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for i in 0..len {
        let result_index: usize = (16 - len + i).try_into().unwrap();
        let input_index: usize = i.try_into().unwrap();
        padded[result_index] = bytes[input_index];
    }
    padded
}

pub fn parse_tag(data: &[u8], offset: usize) -> (u16, u8) {
    let t: u16 = data[offset].into();

    if t & 0x1f != 0x1f {
        (t, 1)
    } else {
        let t = t << 8;
        let t2: u16 = data[offset + 1].into();
        (t | t2, 2)
    }
}

pub fn parse_length(data: &[u8], offset: usize) -> (u128, u8) {
    let ln: u8 = data[offset].into();
    let offset = offset + 1;

    if ln > 0x80 {
        let n_bytes: u8 = ln - 0x80;
        let be_bytes: [u8; 16] =
            add_u128_leading_zeroes(&data[offset..], n_bytes.try_into().unwrap());
        let ln: u128 = u128::from_be_bytes(be_bytes);
        (ln, n_bytes + 1)
    } else {
        (ln.into(), 1)
    }
}
